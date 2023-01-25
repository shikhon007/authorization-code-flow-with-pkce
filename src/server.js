const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const query_string = require('querystring');
const express = require('express');
const handlebars = require('express-handlebars');
const path = require('path');
const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');
const request = require('request-promise');
const session = require('express-session');
const { Router } = require('express');

// loading env vars from .env file
require('dotenv').config();

const nonceCookie = 'auth0rization-nonce';
let oidcProviderInfo;

const app = express();

app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser(crypto.randomBytes(16).toString('hex')));
app.use(
  session({
    secret: crypto.randomBytes(32).toString('hex'),
    resave: false,
    saveUninitialized: false
  })
);
app.engine('handlebars', handlebars());
app.set('view engine', 'handlebars');
app.set('views', path.join(__dirname, 'views'));

// authorization code flow
function validateIDToken(idToken, nonce) {
  const decodedToken = jwt.decode(idToken);
  console.log('decodedToken', decodedToken);
  const {
    nonce: decodedNonce,
    aud: audience,
    exp: expirationDate,
    iss: issuer
  } = decodedToken;
  const currentTime = Math.floor(Date.now() / 1000);
  const expectedAudience = process.env.CLIENT_ID;

  if (
    audience !== expectedAudience ||
    decodedNonce !== nonce ||
    expirationDate < currentTime ||
    issuer !== oidcProviderInfo['issuer']
  )
    throw Error();
  // return the decoded token
  return decodedToken;
}

//code verifier
function base64URLEncode(str) {
  return str
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}
const verifier = base64URLEncode(crypto.randomBytes(32));

// code challenge
function sha256(buffer) {
  return crypto
    .createHash('sha256')
    .update(buffer)
    .digest();
}
const challenge = base64URLEncode(sha256(verifier));

app.get('/', (req, res) => {
  res.render('index');
});

app.get('/profile', (req, res) => {
  const { idToken, decodedIdToken } = req.session;
  //console.log('decodeIdToken', decodedIdToken);
  res.render('profile', {
    idToken,
    decodedIdToken
  });
});

app.get('/login', (req, res) => {
  // define constants for the authorization request
  const authorizationEndpoint = oidcProviderInfo['authorization_endpoint'];
  //const responseType = 'id_token';
  const responseType = 'code';
  const code_challenge = challenge;
  const code_challenge_method = 'S256';
  //const scope = 'openid profile email';
  const scope = 'openid email profile read:to-dos delete:to-dos';
  const clientID = process.env.CLIENT_ID;
  const redirectUri = 'http://localhost:3000/callback';
  //const responseMode = 'form_post';
  // const responseMode = 'query';
  const audience = process.env.API_IDENTIFIER;
  const nonce = crypto.randomBytes(16).toString('hex');

  // define a signed cookie containing the nonce value
  const options = {
    maxAge: 1000 * 60 * 15,
    httpOnly: true, // The cookie only accessible by the web server
    signed: true // Indicates if the cookie should be signed
  };

  const authURL = `${authorizationEndpoint}?${query_string.stringify({
    response_type: responseType,
    scope: scope,
    client_id: clientID,
    redirect_uri: redirectUri,
    nonce: nonce,
    code_challenge: code_challenge,
    code_challenge_method: code_challenge_method,
    audience: audience
  })}`;

  // add cookie to the response and issue a 302 redirecting user
  res.cookie(nonceCookie, nonce, options).redirect(authURL);
});

app.get('/callback', async (req, res) => {
  //********  Implicit Code Flow    ****/

  // // take nonce from cookie
  // const nonce = req.signedCookies[nonceCookie];
  // // delete nonce
  // delete req.signedCookies[nonceCookie];
  // // take ID Token posted by the user
  // const { id_token } = req.body;

  // // decode token
  // const decodedToken = jwt.decode(id_token, { complete: true });
  // // get key id
  // const kid = decodedToken.header.kid;
  // // get public key
  // const client = jwksClient({
  //   jwksUri: oidcProviderInfo['jwks_uri']
  // });
  // client.getSigningKey(kid, (err, key) => {
  //   const signingKey = key.publicKey || key.rsaPublicKey;
  //   // verify signature & decode token
  //   const verifiedToken = jwt.verify(id_token, signingKey);
  //   // check audience, nonce, and expiration time
  //   const {
  //     nonce: decodedNonce,
  //     aud: audience,
  //     exp: expirationDate,
  //     iss: issuer
  //   } = verifiedToken;
  //   const currentTime = Math.floor(Date.now() / 1000);
  //   const expectedAudience = process.env.CLIENT_ID;
  //   if (
  //     audience !== expectedAudience ||
  //     decodedNonce !== nonce ||
  //     expirationDate < currentTime ||
  //     issuer !== oidcProviderInfo['issuer']
  //   ) {
  //     // send an unauthorized http status
  //     return res.status(401).send();
  //   }
  //   req.session.decodedIdToken = verifiedToken;
  //   req.session.idToken = id_token;

  //   // send the decoded version of the ID Token
  //   res.redirect('/profile');
  // });

  // **** Authorization Code Flow ****//

  // console.log('req query', req.query);
  const { code, state } = req.query;
  //console.log('code', code);

  const codeExchangeOptions = {
    grant_type: 'authorization_code',
    client_id: process.env.CLIENT_ID,
    code_verifier: verifier,
    code: code,
    redirect_uri: 'http://localhost:3000/callback'
  };

  const codeExchangeResponse = await request.post(
    `https://${process.env.OIDC_PROVIDER}/oauth/token`,
    { form: codeExchangeOptions }
  );

  // console.log('codeExchangeResponse', codeExchangeResponse);
  // parse response to get tokens
  const tokens = JSON.parse(codeExchangeResponse);
  //console.log('access_token', tokens.id_token);
  req.session.accessToken = tokens.access_token;
  // extract nonce from cookie
  const nonce = req.signedCookies[nonceCookie];
  //console.log('nonce', nonce);
  delete req.signedCookies[nonceCookie];

  try {
    req.session.decodedIdToken = validateIDToken(tokens.id_token, nonce);
    console.log('decodetoken', req.session.decodedIdToken);
    req.session.idToken = tokens.id_token;
    res.redirect('/profile');
  } catch (error) {
    res.status(401).send();
  }
});

app.get('/to-dos', async (req, res) => {
  const delegatedRequestOptions = {
    url: `http://localhost:3001`,
    headers: {
      Authorization: `Bearer ${req.session.accessToken}`
    }
  };
  // console.log('accessToken', req.session.accessToken);
  try {
    const delegatedResponse = await request(delegatedRequestOptions);
    const toDos = JSON.parse(delegatedResponse);

    res.render('to-dos', {
      toDos
    });
  } catch (error) {
    res.status(error.statusCode).send(error);
  }
});

app.get('/remove-to-do/:id', async (req, res) => {
  const deleteRequest = {
    url: `http://localhost:3001/${req.params.id}`,
    headers: {
      Authorization: `Bearer ${req.session.accessToken}`
    }
  };

  try {
    let response = await request.delete(deleteRequest);
    const toDos = JSON.parse(response);
    res.render('to-dos', {
      toDos
    });
  } catch (error) {
    res.status(error.statusCode).send(error);
  }
});

const { OIDC_PROVIDER } = process.env;
const discEnd = `https://${OIDC_PROVIDER}/.well-known/openid-configuration`;

//console.log('discEnd', discEnd);
request(discEnd)
  .then(res => {
    oidcProviderInfo = JSON.parse(res);
    app.listen(3000, () => {
      console.log(`Server running on http://localhost:3000`);
    });
  })
  .catch(error => {
    console.error(error);
    console.error(`Unable to get OIDC endpoints for ${OIDC_PROVIDER}`);
    process.exit(1);
  });
