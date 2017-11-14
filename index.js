const promisify = require('es6-promisify');
const log = require('debug')('r2:pwless');

module.exports = function Pwless(app, conf) {
  const getConf = conf || app.config('jwt');
  if (!getConf) {
    return log('jwt config not found!');
  }

  if (!app.hasServices('Token')) {
    return false;
  }

  const { secret, expiresIn, userModel = 'profile' } = getConf;
  const Token = app.service('Token');
  const mUser = app.service('Mongoose').model(userModel);
  const render = promisify(app.render, app);

  const getToken = tokenData => (
    Object.assign(tokenData, {
      expires: app.utils.expiresIn(expiresIn),
    })
  );

  return {
    createToken(data = {}, type = 'login') {
      Object.assign(data, { type });
      return Token.create(data);
    },

    sendToken(tokenData, mailData) {
      const { email } = tokenData;
      const { template, subject, from } = mailData;
      const data = { tokenData, mailData };
      const Mailer = app.service('Mailer'); // for unit test (override service)
      return render(template, data)
        .then(html => Mailer.sendMail({ from, to: email, subject, html }));
    },

    login(authToken) {
      return Token.check(authToken, 'login')
        .then((data) => {
          const { email } = data;
          return mUser.findOneOrError({ email, isEnabled: true, isVerified: true });
        })
        .then((data) => {
          Object.assign(data, { lastLogin: Date.now() });
          return data.save();
        })
        .then((data) => {
          const tokenData = {
            user: data.id,
            expires: app.utils.expiresIn(expiresIn),
          };

          const { token, expires } = app.utils.getToken(tokenData, secret);
          return Object.assign(data.toJSON(), { token, expires });
        });
    },

    refresh(accessToken) {
      if (typeof accessToken === 'string') {
        return app.utils.accessToken(accessToken, getConf)
          .then(decoded => app.utils.getToken(getToken(decoded), secret));
      }

      return Promise.resolve(app.utils.getToken(getToken(accessToken), secret));
    },
  };
};
