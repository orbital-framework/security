<?php

namespace Orbital\Security;

use \Orbital\Framework\Request;
use \Orbital\Http\Session;

abstract class Security {

    /**
     * Strip HTML tags from value
     * Recommended to use in ALL user and browser input values
     * @return string
     */
    public static function stripTags($value){
        $value = strip_tags($value);
        return $value;
    }

    /**
     * Escape HTML tags from value
     * Recommended to use in ALL user and browser input values
     * @return string
     */
    public static function escapeHTML($value){
        $value = htmlspecialchars($value);
        return $value;
    }

    /**
     * Escape individual arguments to shell from value
     * Recommended to use in ALL user and browser input values
     * Not recommended if shell are executed on Windows
     * @return string
     */
    public static function escapeShell($value){
        $value = escapeshellarg($value);
        return $value;
    }

    /**
     * Retrieve CSRF token from request
     * @return mixed
     */
    public static function getCsrfKey(){

        $csrf = Request::request('csrf');

        if( !$csrf ){
            $csrf = Request::header('X-CSRF-Token');
        }

        if( !$csrf ){
            $csrf = NULL;
        }

        return $csrf;
    }

    /**
     * Generate and store CSRF key
     * @param string $scope
     * @return string
     */
    public static function generateCsrfKey($scope = 'csrf'){

        $id = (string) Session::id();
        $token = bin2hex(random_bytes(32));
        $token = sha1($token. '|'. $id. '|'. $scope);

        Session::set('csrf_'. $scope, $token);

        return $token;
    }

    /**
     * Retrieve CSRF key
     * @param string $scope
     * @return string
     */
    public static function retrieveCsrfKey($scope = 'csrf'){

        $token = Session::get('csrf_'. $scope);

        if( !$token ){
            $token = self::generateCsrfKey($scope);
        }

        return $token;
    }

    /**
     * Return CSRF form input
     * @param string $scope
     * @return string
     */
    public static function csrfInput($scope = 'csrf'){
        $token = self::retrieveCsrfKey($scope);
        return '<input type="hidden" name="csrf" value="'. $token. '"/>';
    }

    /**
     * Validate CSRF key
     * @param string $key
     * @param string $scope
     * @return boolean
     */
    public static function validateCsrfKey($key = NULL, $scope = 'csrf'){

        if( $key === NULL ){
            $key = self::getCsrfKey();
        }

        $token = self::retrieveCsrfKey($scope);

        if( !$token OR !$key ){
            return FALSE;
        }

        return (boolean) hash_equals($token, $key);
    }

}