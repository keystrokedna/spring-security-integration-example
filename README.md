### Spring Security and KeystrokeDNA integration example



Here you can see an example of how to integrate a new layer of biometric security created by Keystroke DNA to your Java application based on the Spring framework. It's easy to do, very cool, and is virtually invisible for your end users. But the best part is it's very effective in preventing fraud even when your users' credentials are lost, stolen, or shared. You can find more detailed information about integration and much more on [our site](https://keystrokedna.com/documentation/)

We will also use a TOTP with Google Authenticator in this example, but only in a few special cases that will be described below.



Before we begin, it would be great if you would [sign up](https://keystrokedna.com/join) for our Beta Program and get your own App ID and App Secret. To see the full power of Keystroke DNA in action, you'll have to setup your application first in an `application.yml` file.



Please, set up your App ID and Secret

```yaml
ksdna:
  key: '{{YOUR_KSDNA_APP_ID}}'
  secret: '{{YOUR_KSDNA_APP_SECRET}}'
```



Next, you need to provide your test user credentials. Be aware that the name should be at least **8 characters long**. It's great to use something here that you type a lot every day, like your email or full name. Passwords don't matter for this, so they can just be the same for all users. Also, to really understand how precise Keystroke DNA is and how it protects your users, it would be best to have a colleague or friend nearby to test logging in to each others account.

```yaml
security:
  users:
    -
      name: 'firstuser@domain.com'
      pass: 'password'
    -
      name: 'seconduser@domain.com'
      pass: 'password'
```



If you have already checked our documentation, you know that sometimes our system may consider a user's login attempt as suspicious or it may need the user's involvement to confirm the use of a new device. Taking into account your current login flow, you can use one of the following approaches:

- Ask your user to login from a previously approved device that's already been confirmed

- Use any third-party authentication factor to confirm the authenticity of the user

  

Now is the time when you can test it all out by setting `use2fa` property to `true` or `false`

```yaml
ksdna:
  use2fa: true
```

Depending on what property you choose, this example will demonstrate either approach. As a third party authentication factor, we will use TOTP with Google Authenticator, which you probably already have installed on your phone. If you turned off your `use2fa` option, there would be no need to type any codes, and you will be asked to simply log in from an already confirmed device.



In case the score is suspicious your attempt will be rejected if `use2fa` is `false`. On the other hand, you will be asked to type in TOTP if it's set up as `true`.



So, no more words, just more code. You can always verify and compare your code with our [documentation](https://keystrokedna.com/documentation/)



P.S. Don't take this example as a best practice in Spring Security. It's just an example of a Keystroke DNA integration and should be used for you to develop your own approach :)