<?php declare(strict_types = 1);

/**
 * [Cascade Media]
 * @author Grant Kellie : contact@cascade.media
 * @link: https://cascade.media
 * @copyright 2022 Grant Kellie | Cascade Media
 * @license   
 *  - You may not alter or remove any copyright or other notice from this file.
 *  - Unauthorized copying of this file, via any medium is strictly prohibited, Proprietary and confidential.
 *  - You may not reproduce or distribute any of this file or its contents.
 */

namespace App\Modules\Utilities;

class Cryptography 
{

    /**
     * @property project_directory
     * Aquires the Symfony project directory
     * Config can be found under services.yaml
     */
    private $project_directory;


    /**
     * @method __construct
     * Injects parameters from services.yaml
     * @param $project_directory
     * accesses symfonys kernel.project_dir property
     */
    public function __construct($project_directory = null){
        $this->project_directory = $project_directory;    
    }


/*********************************************************************************************
    Key Management
*********************************************************************************************/

    /**
     * @method generateKey
     * Generates a key for Encryption & Decryption, Hashes
     * 
     * @param string $type
     * Valid requests
     * - HMAC, Hash
     * - Encryption
     * 
     * @param bool $high_entropy
     * Determains the complexity of randomness required in the key. 
     * - True : high entropy (slower, but far more random and complex)
     * - False : low entropy (faster, but weaker)
     * 
     * @param array $options
     * Allows the use of different ciphers and complexities
     * 
     * @return $key
     * a bespoke key specified by the developer for use in the task required.
     * 
     */  
    public function generateKey(string $type = null, array $options = null) {
        if(strtolower($type) === 'encryption') $key = $this->generateEncryptionKey($options);
        else if (strtolower($type) === 'hash' ?: 'hmac') $key = $this->generateSalt($options);
        return sodium_bin2hex($key);    
    }


    /**
     * generateEncryptionKey
     * On Request from the generateKey Function, shall generate a 256 bit random key
     * 
     * @see: https://www.php.net/manual/en/function.sodium-crypto-aead-xchacha20poly1305-ietf-keygen.php
     *
     * @param array|null $options
     * @return function
     */
    private function generateEncryptionKey(array $options = null){
        if(empty($options)) return sodium_crypto_aead_xchacha20poly1305_ietf_keygen();
    }


    /**
     * generateSalt
     * Generates a mew Salt on each request     * 
     * @see: https://www.php.net/manual/en/function.sodium-crypto-pwhash.php
     * 
     * @param array|null $options
     * @return function
     */
    private function generateSalt(array $options = null){
        return random_bytes(SODIUM_CRYPTO_PWHASH_SALTBYTES);
    }

    /**
     * @method sodiumGenerateNonce
     * Generates a new Nonce on each request.
     *
     * @see Cipher information: AEAD_XCHACHA20_POLY1305_IETF
     * Uses cipher AEAD_XCHACHA20_POLY1305_IETF for Nonce
     * 
     * @return function    
     */  
    private function generateNonce(){
        return random_bytes(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);
    }


    /**
     * storeKey
     * Creates a file and stores the key on the server.
     *
     * @param string $directory
     * @param mixed $key
     * @param string $keyname
     * @param string $method
     * @return void
     */
    public function storeKey(string $directory, mixed $key, string $keyname, string $method = 'protected'){
        $file = $directory.'/'.$keyname;
        if (!is_dir($directory)) mkdir($directory, 0755, true); // Check and create directory if it doesn't exist
        if(!file_exists($file)) file_put_contents($file, $key); // Make file if it doesn't exist.
        if (file_exists($file) && strtolower($method) === 'overwrite') file_put_contents($file, $key); // Make file if it doesn't exist.
        if(filesize($file) === 0) throw new \Exception("The file failed to store the key.");        
    }


    /**
     * fetchKey
     * Request the specified key if it exsists
     * @param string $filepath
     * @return $key
     * @throws Exception
     */
    public function fetchKey(string $filepath){
        if (file_exists($filepath)) return file_get_contents($filepath);
        else throw new \Exception("The file you are looking for could not be located.");     
    }

    private function checksum(){

    }

    

/*********************************************************************************************
    Sodium HMAC, Encryption & Decryption
*********************************************************************************************/

    /**
     * @method sodium_encrypt
     * @param mixed $data
     * encrypt message and combine with nonce
     * Sodium_bin2hex offers side-channel atteck attack mitigation.
     * 
     * @see Cipher information: AEAD_XCHACHA20_POLY1305_IETF
     * Uses cipher AEAD_XCHACHA20_POLY1305_IETF to Encrypt
     * 
     * @link https://owasp.org/www-pdf-archive/Side_Channel_Vulnerabilities.pdf
     */
    public function encrypt(string $key, mixed $data){  
        $key = sodium_hex2bin($key);
        $nonce = $this->generateNonce();
        
        if(is_array($data)) $encrypted = sodium_bin2hex($nonce . sodium_crypto_aead_xchacha20poly1305_ietf_encrypt(json_encode($data), '', $nonce, $key)); 
        else $encrypted = sodium_bin2hex($nonce . sodium_crypto_aead_xchacha20poly1305_ietf_encrypt($data, '', $nonce, $key));

        // Clears sensetive data in memory
        $key = $this->clearMemory($key); 
        $nonce = $this->clearMemory($nonce);
        $data = $this->clearMemory(serialize($data));
        
        return $encrypted;
    }


    /**
     * @method sodium_encrypt
     * @param mixed $cipher_data
     * 
     * Decodes $cipher_data through sodium_hextobin.
     * Gets the Nonce and cipher_data from $decoded.
     * Clears any sensetive data stored in memory.
     * If data is json_encoded, the data is decoded then returned.
     * Else the data is returned in a string fromat.
     */
    public function decrypt(string $key, mixed $cipher_data){
        $key = sodium_hex2bin($key);
        $decoded = sodium_hex2bin($cipher_data);  // unpack/decode sodium_bin2hex
        
        if ($decoded === false) throw new \Exception('Decoding failed');    
        if (mb_strlen($decoded, '8bit') < (SODIUM_CRYPTO_SECRETBOX_NONCEBYTES + SODIUM_CRYPTO_SECRETBOX_MACBYTES)) throw new \Exception('The message was truncated');
  
        // Get Nonce and cipher_data from $decoded
        $nonce = mb_substr($decoded, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES, '8bit');
        $cipher_data = mb_substr($decoded, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES, null, '8bit');
        $decrypted = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt($cipher_data, '', $nonce, $key);

        // Clears sensetive data in memory
        $key = $this->clearMemory($key); 
        $nonce = $this->clearMemory($nonce);
        $cipher_data = $this->clearMemory(serialize($cipher_data));
                
        $decrypted_json = json_decode($decrypted);
        if($decrypted_json) return $decrypted_json;
        else return $decrypted;
    }




    /**
     * @method blindIndex
     * @param mixed $data
     * Sodium (Searchable Encryption)
     * 
     * Used to form an determain a hashed plaintext value
     * 
     * The string sent can be stored in memory / database and later be queried
     * by looking up the hashed value.
     * 
     * String -> HMAC -> Search Stored -> Match or Fail
     */
    public function blindIndex(string $salt, mixed $data, bool $highEntropy = true){
        $salt = sodium_hex2bin($salt);
        if($highEntropy === true){
            return sodium_bin2hex(sodium_crypto_pwhash(
                64,
                $data,
                $salt, 
                SODIUM_CRYPTO_PWHASH_OPSLIMIT_SENSITIVE,
                SODIUM_CRYPTO_PWHASH_MEMLIMIT_SENSITIVE,
                SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13
            ));            
        } else {
            return sodium_bin2hex(sodium_crypto_pwhash(
                32,
                $data,
                $salt, 
                SODIUM_CRYPTO_PWHASH_OPSLIMIT_MODERATE,
                SODIUM_CRYPTO_PWHASH_MEMLIMIT_MODERATE,
                SODIUM_CRYPTO_PWHASH_ALG_DEFAULT 
            ));
        }
    }




    /**
     * @method clearMem
     * @param string $data
     * @link https://doc.libsodium.org/memory_management#zeroing-memory
     * sodium_memzero clears sensetive data from memory.
     * As this method only accepts string values, non-string values are serialized
     * before being assigned to memory cleansing. 
     */
    private function clearMemory(mixed $data){
        return sodium_memzero($data); 
    }



/*********************************************************************************************
    Argon2 Password Hashing & Salting
*********************************************************************************************/

    /**
     * @property argon2id_algorithm
     * Delcares wich Algorithm should be used.
     * This propery holds the PASSWORD_ARGON2ID hashing algorithm
     * @link https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-argon2-03#section-3.1
     * @link https://www.password-hashing.net/argon2-specs.pdf
     * @link https://www.php.net/manual/en/function.password-hash.php
     */
    private $argon2id_algorithm = PASSWORD_ARGON2ID;


    /**
     * @property argon2argon2id_options
     * @uses Argon2lib
     * Holds the array for default values of the 
     * PASSWORD_ARGON2ID hashing algorithm.
     * 
     * PASSWORD_ARGON2_DEFAULT_MEMORY_COST: 65536 Bytes
     * PASSWORD_ARGON2_DEFAULT_TIME_COST: 4 
     * PASSWORD_ARGON2_DEFAULT_THREADS: 1
     * 
     * @link https://wiki.php.net/rfc/argon2_password_hash
     * 
     */
    private $argon2id_options = [
        'memory_cost' => PASSWORD_ARGON2_DEFAULT_MEMORY_COST,
        'time_cost' => PASSWORD_ARGON2_DEFAULT_TIME_COST,
        'threads' => PASSWORD_ARGON2_DEFAULT_THREADS
    ];

    
    /**
     * @method argon2id_rehashPassword
     * verifies if the argon2id options [memory_cost, time_cost, threads] are different from the original
     * and allow for a rehash with the updated configuration.
     */
    public function argon2id_rehashPassword(string $password, string $hash, $new_options = null){
        if(password_needs_rehash($hash, $this->argon2id_algorithm, $new_options)){
            return $this->argon2id_password($password, $new_options);
        }
    }


    /**
     * @method argon2id_password
     * Cryptographically secures passwords using the Argin2id algorithm
     * Argon2id is used for side-channel protection and time-memory trade-off
     * 
    */
    public function argon2id_password(string $password, array $options = null){        
        if(empty($options)) $options = $this->argon2id_options;
        return password_hash($password, $this->argon2id_algorithm, $options);  
    }


    /**
     * @method argon2id_options
     * @param array|null $options
     * @return $new_options
     * 
     * Allows the default options to be overwritten by multiplied increments.
     */
    public function argon2id_options(array $options = null){
        $new_options = [];
        !empty($options['memory_cost']) ? $new_options['memory_cost'] = $this->argon2id_options['memory_cost'] * $options['memory_cost'] : $this->argon2id_options['memory_cost'];
        !empty($options['time_cost']) ? $new_options['time_cost'] = $this->argon2id_options['time_cost'] * $options['time_cost'] : $this->argon2id_options['time_cost'];
        !empty($options['threads']) ? $new_options['threads'] = $this->argon2id_options['threads'] * $options['threads'] : $this->argon2id_options['threads']; 
        return $new_options;      
    }






    /**
     * Cipher Information
     * 
     * 
     * AEAD_XCHACHA20_POLY1305_IETF
     * @see https://doc.libsodium.org/secret-key_cryptography/aead
     * 
     * Cipher Availability and interoperability
     * Key Size: 256 Bits
     * Nonce Size: 192 Bits 
     * Block Size: 512 Bits
     * 
     * Cipher Limitations
     * Max Bytes for a single (Key, Nonce): No Practical limits (~2^64 Bytes)
     * Max Bytes for a single Key: Up to 2^64* messages, no practical total size limits
     * 
     * ********************************************************************************************
     * Security Notes
     * 
     * 
     * Sodium_bin2hex offers side-channel atteck attack mitigation.
     * @see https://owasp.org/www-pdf-archive/Side_Channel_Vulnerabilities.pdf
     * 
     */
}
