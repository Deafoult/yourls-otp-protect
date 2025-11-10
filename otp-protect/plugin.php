<?php
/*
Plugin Name: OTP Protect
Plugin URI: https://github.com/Deafoult/yourls-otp-protect
Description: Secure YOURLS instances so that only people with a valid OTP secret can create new short URLs.
Version: 0.3
Author: Deafoult
Author URI: https://github.com/Deafoult
*/

require_once('src/SimpleAuthenticator.php');
require_once('src/DataStore.php');
use SebastianDevs\SimpleAuthenticator;

// No direct call
if( !defined( 'YOURLS_ABSPATH' ) ) die();

yourls_add_action( 'plugins_loaded', 'otpprotect_add_settings' );
function otpprotect_add_settings() {
    yourls_register_plugin_page( 'otpprotect', 'OTP Protect', 'otpprotect_settings_page' );	
}

yourls_add_action( 'pre_add_new_link', 'otpprotect_check_otp' );
function otpprotect_check_otp( $args ) {
    
    // Get the submitted OTP value. The name 'otp' is from the frontend form.
    $submitted_otp = $_REQUEST['otp'] ?? '';

	// Retrieve and unserialize the OTP data from the database.
	$otpprotect_DataSerialized = yourls_get_option("otpprotect_Data");
    $otpprotect_Data = DataStore::unserializeData($otpprotect_DataSerialized);

    $is_valid_otp = false;
    
	// Iterate through all stored OTP secrets and check for a match.
	foreach($otpprotect_Data as $item){


        $url = $item->otp_url;
        $url_query = parse_url($url,PHP_URL_QUERY);
        parse_str($url_query, $url_params);
        $secret = $url_params['secret'];
		$codeLength = isset($url_params['digits']) ? (int)$url_params['digits'] : 6;
		$algorithm = isset($url_params['algorithm']) ? $url_params['algorithm'] : 'SHA1';

		// Configure the SimpleAuthenticator with the correct settings.
		$auth = new SimpleAuthenticator($codeLength,$algorithm);
        $is_valid_otp |= $auth->verifyCode($secret, $submitted_otp, 1);

    }

    // If the OTP check fails, terminate the process.
    if ( !$is_valid_otp ) {
        
        $longurl = $args['url']; // Get the long URL from the arguments.
        
        // Terminate YOURLS and display an error message. This prevents the link from being saved.
        yourls_die( 
            yourls__('OTP check failed. The link could not be saved.'), 
            yourls__('OTP Error'), 
            $longurl // URL for the error page.
        );
        // Note: yourls_die() stops the execution here.
    }
    
    // If the check is successful, the function simply returns,
    // and YOURLS proceeds with saving the link.
}


function otpprotect_settings_page() {

    // Check if the config form has been submitted
    if (isset($_POST['otpprotect_config_qr_generator_url'])) {
        // Verify nonce
        yourls_verify_nonce('random_shorturl_settings');

        // Sanitize and save the settings
        yourls_update_option('otpprotect_config_qr_generator_url', yourls_sanitize_url($_POST['otpprotect_config_qr_generator_url']));
        yourls_update_option('otpprotect_config_otp_once', ($_POST['otpprotect_config_otp_once'] == 'yes' ? 'yes' : 'no'));
        yourls_update_option('otpprotect_config_crpto_algorithm', in_array($_POST['otpprotect_config_crpto_algorithm'], ['SHA1', 'SHA256', 'SHA512']) ? $_POST['otpprotect_config_crpto_algorithm'] : 'SHA1');
        yourls_update_option('otpprotect_config_otp_length', intval($_POST['otpprotect_config_otp_length']));
        yourls_update_option('otpprotect_config_logging', ($_POST['otpprotect_config_logging'] == 'yes' ? 'yes' : 'no'));
        
        echo "<p style='color: green;'>Settings saved!</p>";
    }

    // Load saved settings
    $qr_generator_url = yourls_get_option('otpprotect_config_qr_generator_url', 'https://api.qrserver.com/v1/create-qr-code/?size=150x150&data=');
    $otp_once = yourls_get_option('otpprotect_config_otp_once', 'no');
    $crypto_algorithm = yourls_get_option('otpprotect_config_crpto_algorithm', 'SHA256');
    $otp_length = yourls_get_option('otpprotect_config_otp_length', 6);
    $logging = yourls_get_option('otpprotect_config_logging', 'no');

	// Attempt to retrieve and unserialize the OTP data from the database.
	$otpprotect_DataSerialized = yourls_get_option("otpprotect_Data");
	if($otpprotect_DataSerialized !== false){
		// If data exists, unserialize it.
		$otpprotect_Data = DataStore::unserializeData($otpprotect_DataSerialized);
	}else{
		// Otherwise, create a new DataStore object.
		$otpprotect_Data = new DataStore();
	}

    // Check if a new ID is being added.
    if( isset( $_REQUEST['otpprotect_add_id'] ) ) {
        // Verify the nonce to prevent CSRF attacks.
        yourls_verify_nonce( 'random_shorturl_settings' );
        
        // Create a new SimpleAuthenticator instance.
        $auth = new SimpleAuthenticator();
        
        // If a secret is provided, use it; otherwise, create a new random secret.
        if(empty($_REQUEST['otpprotect_secret'])){
            $secret = $auth->createSecret();
        }else{
            $secret = $_REQUEST['otpprotect_secret'];
        }

        // Create the OTP URL and add the new object to the DataStore.
        $urlencoded = 'otpauth://totp/YOURLS?secret=' . $secret .'&algorithm=' . $crypto_algorithm . '&digits=' . $otp_length;
		$otpprotect_Data->addObject($_REQUEST['otpprotect_add_id'], $urlencoded);
		
		// Update the serialized data in the database.
		yourls_update_option('otpprotect_Data', $otpprotect_Data->serializeData());	
    }

	// Check if an ID is being deleted.
	if( isset( $_REQUEST['otpprotect_delete_id'] ) ) {
        // Verify the nonce to prevent CSRF attacks.
    	yourls_verify_nonce( 'random_shorturl_settings' );
        
        // Delete the object from the DataStore and update the database.
		$otpprotect_Data->deleteObject($_REQUEST['otpprotect_delete_id']);
		yourls_update_option('otpprotect_Data', $otpprotect_Data->serializeData());	
    }

	// Create a nonce for the settings form.
	$nonce = yourls_create_nonce( 'random_shorturl_settings' );
	
    // Prepare options for select fields
    $otp_once_options = '';
    foreach (['yes', 'no'] as $val) {
        $selected = ($otp_once == $val) ? 'selected' : '';
        $otp_once_options .= "<option value='$val' $selected>$val</option>";
    }

    $crypto_algorithm_options = '';
    foreach (['SHA1', 'SHA256', 'SHA512'] as $val) {
        $selected = ($crypto_algorithm == $val) ? 'selected' : '';
        $crypto_algorithm_options .= "<option value='$val' $selected>$val</option>";
    }

    $logging_options = '';
    foreach (['yes', 'no'] as $val) {
        $selected = ($logging == $val) ? 'selected' : '';
        $logging_options .= "<option value='$val' $selected>$val</option>";
    }

	// Display the form for adding a new ID.
		echo <<<HTML
			<main>
            	<h2>OTP Protect Settings</h2>
				<form method="post">
					<input type="hidden" name="nonce" value="$nonce" />
					<h3>URL Generation</h3>
					<p>
                		<label>QR Generator URL:</label>
                		<input type="text" name="otpprotect_config_qr_generator_url" value="$qr_generator_url" style="width: 100%;" />
            		</p>
					<p>
                		<label>Crypto Algorithm</label>
                		<select name="otpprotect_config_crpto_algorithm">
							$crypto_algorithm_options
						</select>
					</p>
					<p>
                		<label>OTP Length</label>
                		<input type="number" name="otpprotect_config_otp_length" value="$otp_length" min="6" max="10" />
					</p>
					<h3>Regular Settings</h3>
					<p>
                		<label>(Not yet implemented)Allow OTP Token only once:</label>
                		<select name="otpprotect_config_otp_once">
							$otp_once_options
						</select>
					</p>
					<p>
                		<label>(Not yet implemented)Activate logging:</label>
                		<select name="otpprotect_config_logging">
							$logging_options
						</select>
					</p>
					<p><input type="submit" value="Save Config" class="button" /></p>
				</form>

				<hr />

				<h2>Add new OTP ID</h2>
				<p>Enter an ID and optionally a secret to create a new OTP entry. If no secret is provided, a random one will be generated.</p>
	    		<form method="post">
            		<input type="hidden" name="nonce" value="$nonce" />
					<p>
                		<label>ID:</label>
                		<input type="text" name="otpprotect_add_id" />
            		</p>
            		<p>
                		<label>Secret:</label>
                		<input type="text" name="otpprotect_secret" />
            		</p>
					<p>* or leave empty for random secret</p>
            		<p><input type="submit" value="Add ID" class="button" /></p>
            	</form>
HTML;		
    
	// Loop through and display each stored OTP item.
	foreach($otpprotect_Data as $item){
        $url = urlencode($item->otp_url);
	    echo <<<HTML
			<hr />
			ID: $item->id<br />
			OTP URL: $item->otp_url<br />
			<form method="post">
            	<input type="hidden" name="nonce" value="$nonce" />
				<input type="hidden" name="otpprotect_delete_id" value="$item->id" />
            	<p><input type="submit" value="Delete ID" class="button" /></p>
            	</form>
			<img src="$qr_generator_url$url">

HTML;
	}

	echo <<<HTML
		</main>
HTML;
}

?>