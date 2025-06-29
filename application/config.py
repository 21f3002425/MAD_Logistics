class Config():
    DEBUG = False
    SQLALCHEMY_TRACK_MODIFICATIONS = True

class LocalDevelopmentConfig(Config):
    # database configuration
    SQLALCHEMY_DATABASE_URI = "sqlite:///lmsv2.sqlite3"
    DEBUG = True

    #config for security
    SECRET_KEY = "this_is_a_secret_key" #hash user credentials in the session
    SECURITY_PASSWORD_HASH = "bcrypt" #mechanism to hash passwords
    #explanation of bcrypt(password,salt) :
    #bcrypt is a method which takes a password from form and hashes it using a salt that we defined
    #the salt is a random string which is used to hash the password, it is stored
    #application can be more secure by using a different salt for each user
    SECURITY_PASSWORD_SALT = "this_is_a_password_salt"  #helps in hashing passwords
    WTF_CSRF_ENABLED = False  
    SECURITY_TOKEN_AUTHENTICATION_HEADER = "Authentication-Token"

