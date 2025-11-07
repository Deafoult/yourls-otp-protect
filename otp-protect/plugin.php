<?php
/*
Plugin Name: OTP Protect
Plugin URI: https://github.com/Deafoult/yourls-otp-protect
Description: Secure YOURLS instances so that only people with a valid OTP secret can create new short URLs.
Version: 0.2
Author: deafoult
Author URI: https://github.com/Deafoult
*/

require_once('src/SimpleAuthenticator.php');
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
	$otpprotect_Array = $otpprotect_Data->getAllObjects();

    $is_valid_otp = false;
    
	// Iterate through all stored OTP secrets and check for a match.
	foreach($otpprotect_Array as $item){

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

	// Get all stored OTP objects.
	$otpprotect_Array = $otpprotect_Data->getAllObjects();
    
	// Loop through and display each stored OTP item.
	foreach($otpprotect_Array as $item){
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


/**
 * Manages a collection of objects in an array with serialization capabilities.
 */
class DataStore {
    private array $storage = [];

    // --- CRUD Operations ---

    /**
     * Adds a new object to the store.
     * The object contains an ID and an OTP URL.
     *
     * @param string $id The ID of the object.
     * @param string $otpUrl The OTP URL for the object.
     * @return object The added object.
     */
    public function addObject(string $id, string $otpUrl): object {
        $newObject = (object) [
            'id' => $id,
            'otp_url' => $otpUrl
        ];
        $this->storage[] = $newObject;
        return $newObject;
    }

    /**
     * Deletes an object from the store by its ID.
     *
     * @param string $id The ID of the object to delete.
     * @return bool True on success, false if the object was not found.
     */
    public function deleteObject(string $id): bool {
        foreach ($this->storage as $key => $object) {
            if ($object->id === $id) {
                unset($this->storage[$key]);
                $this->storage = array_values($this->storage); // Re-index the array.
                return true;
            }
        }
        return false;
    }

    /**
     * Returns all objects in the store.
     *
     * @return array An array of all stored objects.
     */
    public function getAllObjects(): array {
        return $this->storage;
    }

    // --- Serialization ---

    /**
     * Serializes the current DataStore instance into a string.
     *
     * @return string The serialized string representing the object's state.
     */
    public function serializeData(): string {
        return serialize($this);
    }

    /**
     * Deserializes a string into a new DataStore instance.
     *
     * @param string $serializedString The serialized string.
     * @return DataStore|null The reconstructed DataStore instance or null on failure.
     */
    public static function unserializeData(string $serializedString): ?DataStore {
        $loadedObject = unserialize($serializedString);

        if ($loadedObject instanceof DataStore) {
            return $loadedObject;
        }
        return null;
    }
}

?>