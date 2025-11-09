

# Plugin for YOURLS : OTP Protect [![Listed in Awesome YOURLS!](https://img.shields.io/badge/Awesome-YOURLS-C5A3BE)](https://github.com/YOURLS/awesome-yourls/)

A plugin for [YOURLS](https://yourls.org/) to protect link creation with a Time-based One-Time Password (TOTP).

## Description

This plugin secures your YOURLS installation by requiring a valid TOTP to create new short URLs. This is useful if you want to share your YOURLS instance with others but still control who can create links.

## Installation

1.  Copy the `otp-protect` folder into the `user/plugins` directory of your YOURLS installation.
2.  Go to the "Manage Plugins" page in your YOURLS admin interface and activate the "OTP Protect" plugin.

## Configuration

1.  After activating the plugin, a new menu item "OTP Protect" will appear in the admin interface.
2.  On the "OTP Protect Settings" page, you can add new OTP secrets.
3.  Enter an `ID` (a descriptive name for the secret, e.g., a username) and optionally a `Secret`. If you leave the `Secret` field empty, a random one will be generated.
4.  Click "Add ID".
5.  A QR code will be displayed. Scan this QR code with your favorite TOTP app (e.g., Google Authenticator, Authy).

## Usage

To use the OTP protection, you need to modify your YOURLS public interface to include an input field for the OTP.

1.  Open the file in your YOURLS installation that contains the main form for creating short URLs. This is often the `index.php` file in the root of your YOURLS installation, but the file might be different depending on your setup.
2.  Find the form where you enter the long URL.
3.  Add the following HTML code inside the form. A good place is right before the submit button.

    ```html
    <p>
        <label for="otp">OTP:</label>
        <input id="otp" type="text" class="text" name="otp" size="6" />
    </p>
    ```
    You can adjust the HTML to fit your site's design. The important part is `name="otp"`.

4.  Now, when creating a new short URL, you will see the "OTP" field. Enter the current TOTP from your authenticator app to create the link.

If the OTP is incorrect, the link creation will fail.

## How it works

The plugin hooks into the `pre_add_new_link` action in YOURLS. Before a new link is added, it checks for a valid OTP in the request.

The OTPs are generated and verified using the `SimpleAuthenticator` class, which is a TOTP implementation based on RFC 6238.

The secrets are stored in the YOURLS database.

## Roadmap

- [ ] **[SECURITY]** Add settings to change the QR-Code generator (e.g. link/placeholder).
- [ ] **[SECURITY]** Prevent token replay (single-use tokens)
- [ ] Add various settings like OTP length, algorithm, etc.
- [ ] Add protection to not allow same id twice.
- [ ] Add Screenshot to Readme

## License

This plugin is released under the MIT License. See the `LICENSE` file for more details.

## Third-Party Licenses

### SimpleAuthenticator.php

The `src/SimpleAuthenticator.php` file is based on `SimpleThenticator` and is licensed under the BSD 2-Clause "Simplified" License.
See `third_party/SimpleThenticator/LICENSE` for license details.
