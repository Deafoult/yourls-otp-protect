<?php
/*
Plugin Name: OTP Protect
Plugin URI: https://github.com/Deafoult/yourls-otp-protect
Description: Secure YOURLS instances so that only people with a valid OTP secret can create new short URLs.
Version: 0.2
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

        $auth = new SimpleAuthenticator();
        $url = $item->otp_url;
        $url_query = parse_url($url,PHP_URL_QUERY);
        parse_str($url_query, $url_params);
        $secret = $url_params['secret'];
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
        $urlencoded = 'otpauth://totp/YOURLS?secret=' . $secret .'&algorithm=SHA256';
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
	
	// Display the form for adding a new ID.
		echo <<<HTML
			<main>
            	<h2>OTP Protect Settings</h2>
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
			<img width="200px" height="200px" src="https://api.qrserver.com/v1/create-qr-code/?size=150x150&data=$url">

HTML;
	}

	echo <<<HTML
		</main>
HTML;
}

?>