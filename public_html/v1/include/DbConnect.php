<?php
 
/**
 * Handling database connection
 *
 */
class DbConnect {
 
    private $conn;
 
    function __construct() {  

        $dotenv = new Dotenv\Dotenv('/var/www/api.jazlife.com/');
        $dotenv->load();
        $dotenv->required('DB_USERNAME', 'DB_PASSWORD', 'DB_HOST', 'DB_NAME')->notEmpty();      
    }
 
    /**
     * Establishing database connection
     * @return database connection handler
     */
    function connect() {
 
		try {
        	$this->conn = new PDO('mysql:host='.$_ENV['DB_HOST'].';charset=UTF8;dbname='.$_ENV['DB_NAME'], $_ENV['DB_USERNAME'], $_ENV['DB_PASSWORD']);
        	return $this->conn;
        } catch(PDOException $e) {
        	echo '{"error": TRUE, "message":'. $e->getMessage() .'}';
   		}
        
    }
 
}
 
?>