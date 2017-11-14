const chai = require('chai');
const r2base = require('r2base');
const r2mongoose = require('r2mongoose');
const r2query = require('r2query');
const r2plugin = require('r2plugin');
const r2system = require('r2system');
const r2token = require('r2token');
const r2pwless = require('../index');
const stubTransport = require('nodemailer-stub-transport');
const nodemailer = require('nodemailer');

const mailer = nodemailer.createTransport(stubTransport());
const { expect } = chai;
process.chdir(__dirname);

const app = r2base();
app.start()
  .serve(r2mongoose, { database: 'r2test' })
  .serve(r2query)
  .serve(r2plugin)
  .serve(r2system)
  .serve(r2token)
  .load('model')
  .serve(r2pwless)
  .into(app);

app.setService(function Mailer() { // eslint-disable-line
  return mailer;
}, 'Mailer');

app.set('view engine', 'ejs');
const Mongoose = app.service('Mongoose');
const Pwless = app.service('Pwless');
const mProfile = app.service('model/profile');

const { secret, expiresIn } = app.config('jwt');
const tokenDataObj = {
  user: '000000000000000000000001',
  expires: app.utils.expiresIn(expiresIn),
};

const encoded = app.utils.getToken(tokenDataObj, secret);
const { token: encodedToken } = encoded;

before((done) => {
  Mongoose.set('debug', false);
  mProfile.create({ email: 'test3@app.com', name: 'Test 3', passwd: 12345, isVerified: true, isEnabled: true })
    .then(() => done())
    .catch(() => done());
});

function dropDatabase(done) {
  this.timeout(0);
  Mongoose.connection.db.dropDatabase();
  done();
}

after(dropDatabase);

describe('r2pwless', () => {
  it('should create token', (done) => {
    Pwless.createToken({ email: 'test@app.com', name: 'Test', slug: 'test' })
      .then((tokenData) => {
        const { email, type, token, data } = tokenData.doc;
        expect(email).to.equal('test@app.com');
        expect(type).to.equal('login');
        expect(token).to.not.equal(undefined);
        expect(data).to.deep.equal({ slug: 'test', name: 'Test' });
        expect(tokenData.created).to.equal(true);
        done();
      })
      .catch(done);
  });

  it('should send token', (done) => {
    Pwless.createToken({ email: 'test2@app.com', name: 'Test 2', slug: 'test2' })
      .then(data => Pwless.sendToken({
        email: 'test@app.com',
      }, {
        template: 'emails/test.ejs',
        subject: 'token mail',
        from: 'noreply@app.com',
        data,
      }))
      .then((data) => {
        expect(data.envelope).to.not.equal(undefined);
        expect(data.envelope.from).to.equal('noreply@app.com');
        expect(data.envelope.to[0]).to.equal('test@app.com');
        expect(data.messageId).to.not.equal(undefined);
        expect(data.response).to.not.equal(undefined);
        done();
      });
  });

  it('should login via token', (done) => {
    Pwless.createToken({ email: 'test3@app.com', name: 'Test 3', slug: 'test3' })
      .then(data => Pwless.login(data.doc.token))
      .then((data) => {
        const { email, token, expires } = data;
        expect(email).to.equal('test3@app.com');
        expect(token).to.not.equal(undefined);
        expect(expires).to.not.equal(undefined);
        done();
      });
  });

  it('should generate refresh token, from token string', (done) => {
    setTimeout(() => {
      Pwless.refresh(encodedToken)
        .then((data) => {
          const { token: newToken } = data;
          expect(newToken).is.not.equal(encodedToken);
          done();
        })
        .catch(done);
    }, 10);
  });

  it('should generate refresh token, from token data', (done) => {
    setTimeout(() => {
      Pwless.refresh(encoded)
        .then((data) => {
          const { token: newToken } = data;
          expect(newToken).is.not.equal(encodedToken);
          done();
        })
        .catch(done);
    }, 10);
  });
});
