const express = require('express');
const app = express();
const bodyParser = require('body-parser');

const xsenv = require('@sap/xsenv');
xsenv.loadEnv();
const services = xsenv.getServices({
    uaa: { tag: 'xsuaa' }
});

const jwtDecode = require('jwt-decode');

const xssec = require('@sap/xssec');
const passport = require('passport');
passport.use('JWT', new xssec.JWTStrategy(services.uaa));
app.use(passport.initialize());
app.use(passport.authenticate('JWT', {
    session: false
}));

app.use(bodyParser.json());

app.get('/srv/display', function (req, res) {
    if (req.authInfo.checkScope('$XSAPPNAME.Display')) {
        let token = jwtDecode(req.authInfo.token);
        let userInfo = {
			"name": req.user.id,
			"emails": req.user.emails,
			"scopes": req.authInfo.scopes,
			"identity-zone": req.authInfo.identityZone,
            "roles": token["xs.system.attributes"]["xs.rolecollections"],
            "user-attributes": token["xs.user.attributes"]
		};
        res.status(200).json(userInfo);
    } else {
        res.status(403).send('Forbidden');
    }
});

app.get('/srv/execute', function (req, res) {
    if (req.authInfo.checkScope('$XSAPPNAME.Execute')) {
        let token = jwtDecode(req.authInfo.token);
        let userInfo = {
			"name": req.user.id,
			"emails": req.user.emails,
			"scopes": req.authInfo.scopes,
			"identity-zone": req.authInfo.identityZone,
            "roles": token["xs.system.attributes"]["xs.rolecollections"],
            "user-attributes": token["xs.user.attributes"]
		};
        res.status(200).json(userInfo);
    } else {
        res.status(403).send('Forbidden');
    }
});

app.get('/srv/edit', function (req, res) {
    if (req.authInfo.checkScope('$XSAPPNAME.Edit')) {
        let token = jwtDecode(req.authInfo.token);
        let userInfo = {
			"name": req.user.id,
			"emails": req.user.emails,
			"scopes": req.authInfo.scopes,
			"identity-zone": req.authInfo.identityZone,
            "roles": token["xs.system.attributes"]["xs.rolecollections"],
            "user-attributes": token["xs.user.attributes"]
		};
        res.status(200).json(userInfo);
    } else {
        res.status(403).send('Forbidden');
    }
});

const port = process.env.PORT || 5001;
app.listen(port, function () {
    console.info('Listening on http://localhost:' + port);
});
