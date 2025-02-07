import base64, os, hashlib,logging
from flask import Flask, request, send_file, jsonify # type: ignore


app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")


# Salt value
SALT = "h4CkCtF"

@app.route('/login', methods=['POST'])
def login():
    # Get JSON data from the request
    #data = request.json
    data = request.get_json(silent=True) or {}

    #Base64 params encoded for GR2, GR4, GR6
    #SHA256 params encoded for GR5, GR7
    #SHA512 for GR1, GR3

    #GR1 nombre del vocalista de slipknot, clave es la canción 2 del album we are not your kind, GR1 todo con hash sha512
    #GR2 nombre del nuevo baterista de slipknot, clave es la canción 4 del album de su mismo nombre, GR2 todo con base 64
    #GR3 apellido del vocalista de korn, cancion que tiene titulo de una discapacidad, GR1 todo con hash sha512
    #GR4 alias del baterista de korn y su ultimo album
    #GR6 ex vocalista de linkin park y cancion 8 del hybrid theory
    #GR5 nombre y apellido del personaje de una afamada serie de hackers, nombre del grupo al que pertenecia y hacia hacking sha256
    #GR7 nombre de uno de los hackers más famosos del mundo que esta muerto, nombre de la gran telco que hackeo por primera vez.

    # Extract username, password, and gr from the JSON
    #username = data.get('username', '')
    #password = data.get('password', '')
    #gr = data.get('gr', '')
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", "")).strip()
    gr = str(data.get("gr", "")).strip()
    combined = "INCORRECTO"
    status = "Invalid Credentials"
    http_code = 200

    username_encoded=""
    password_encoded=""

    if gr=="GR1":
        username_encoded = hashlib.sha512("corey".encode()).hexdigest()
        password_encoded = hashlib.sha512("unsainted".encode()).hexdigest()        
    elif gr=="GR3":
        username_encoded = hashlib.sha512("davis".encode()).hexdigest()
        password_encoded = hashlib.sha512("blind".encode()).hexdigest()       
    elif gr=="GR2":
        # Convert string to bytes
        byte_data_u = "eloy".encode("utf-8")
        byte_data_p = "waitandbleed".encode("utf-8")
        # Encode bytes to Base64
        username_encoded = base64.b64encode(byte_data_u).decode("utf-8")        
        password_encoded = base64.b64encode(byte_data_p).decode("utf-8")        
    elif gr=="GR4":
        # Convert string to bytes
        byte_data_u = "fieldy".encode("utf-8")
        byte_data_p = "requiem".encode("utf-8")
        # Encode bytes to Base64
        username_encoded = base64.b64encode(byte_data_u).decode("utf-8")        
        password_encoded = base64.b64encode(byte_data_p).decode("utf-8")        
    elif gr=="GR6":
        # Convert string to bytes
        byte_data_u = "chester".encode("utf-8")
        byte_data_p = "intheend".encode("utf-8")
        # Encode bytes to Base64
        username_encoded = base64.b64encode(byte_data_u).decode("utf-8")        
        password_encoded = base64.b64encode(byte_data_p).decode("utf-8")       
    elif gr=="GR5":
        username_encoded = hashlib.sha256("elliotalderson".encode()).hexdigest()
        password_encoded = hashlib.sha256("fsociety".encode()).hexdigest()        
    elif gr=="GR7":
        username_encoded = hashlib.sha256("kevinmitnick".encode()).hexdigest()
        password_encoded = hashlib.sha256("pacificbell".encode()).hexdigest()
    else:
        combined = "INCORRECTO"

    #Validate username and password
    logging.info(username_encoded)
    logging.info(username)
    logging.info(password_encoded)
    logging.info(password)
    if (username==str(username_encoded)) and (password==str(password_encoded)):
        combined = f"{username_encoded}{password_encoded}{gr}{SALT}"       

    # Generate SHA-256 hash
    if (combined=='INCORRECTO'):
        client_ip = request.remote_addr  # Get the client's IP address        
        group_key = "Starting reverse console on your ip: "+client_ip+"..... 100%....Hacking Completed!.... >>>----You have been hacked! xD...---"
        http_code = 404
    else:
        # Combine the three terms with the salt
        status = "Access Granted"
        group_key = hashlib.sha256(combined.encode()).hexdigest()
        http_code = 200
    
    # Return the hash as a JSON response
    return jsonify({"group_key": group_key,"status":status}), http_code

@app.route('/logout', methods=['GET'])
def logout():
    status = "Bogus end-point found"
    group_key = hashlib.sha384("dummy".encode()).hexdigest()
    http_code = 200
    return jsonify({"group_key": group_key,"status":status}), http_code

@app.route('/key', methods=['GET'])
def key():
    status = "Bogus end-point found"
    group_key = hashlib.sha384("key".encode()).hexdigest()
    http_code = 200
    return jsonify({"group_key": group_key,"status":status}), http_code

@app.route('/challenge', methods=['POST'])
def challenge():
    # List of 7 valid tokens
    TOKEN_TO_FILE = {
        "70c2df7f6d50809702c45ddf9e3400dafba4b6cd829a07bc72fdcc45539c49a8": "4cae50cafe2a87e2cb7cba9f4fb868d0e8a49566.zip",#challengeGR101
        "1bd0b578a3b018d5cb49b8abfe2b488d05a7f52ebdb69ab4b1d27e0d60378c57": "49eeef09600f53901941714eff5b5a4e658e75a8.zip",#challengeGR202
        "6a0b35dd21adab89e881a4b37e79b24382939ddf714407ec2d7321b130dd42fa": "db13a9cbf6953967d23699a23c14676c010fc9eb.zip",#challengeGR303
        "0f2769d065cc97fa895df64a5d3526eae358d4746eb96e4f21809b89bd208028": "17629369b1b01afdae462ebb60f9de900e6ba597.zip",#challengeGR404
        "775b1e13bf83ea46abdef5b12b84a854f82da872867bae0066a2a509132141f6": "a0099effc98e2d798e67080d3abbf33047720e34.zip",#challengeGR505
        "15ce9218029d6f229ac8238a1da94095c5f2684367e08ccb94ddddac15de2240": "867f1fccac98deabf9cea7b6eb2d260b25782cbd.zip",#challengeGR606
        "765f659eb04b984ee6d9749763076db0e995c314ade24e93ed8c82d9b2dbbaf0": "b6e62f3a3f2bb1a80f736dd1fa1610fbced13226.zip"#challengeGR707
    }
    
    BASE_DIR = os.path.dirname(os.path.abspath(__file__)) 
    PDF_DIRECTORY = os.path.join(BASE_DIR,"pdf_f1l3s/")
    
    """Endpoint to provide PDF files if a valid token is given."""
    
    # Get the token from the request
    data = request.get_json(silent=True) or {}    
    token = str(data.get("token","")).strip()
    logging.info(token)

    # Validate token
    if token not in TOKEN_TO_FILE:
        return jsonify({"error": "Invalid token"}), 403
    else:
        # Get the assigned PDF file for the token
        pdf_filename = TOKEN_TO_FILE[token]
        file_path = os.path.join(PDF_DIRECTORY, pdf_filename)
        
    logging.info(file_path)
    
    # Validate filename (prevent directory traversal attacks)
    #if not pdf_filename or ".." in pdf_filename or "/" in pdf_filename:
    #    return jsonify({"error": "Invalid filename"}), 400

    # Construct full file path
    #file_path = os.path.join(PDF_DIRECTORY, pdf_filename)

    # Check if file exists
    if not os.path.exists(file_path):
        return jsonify({"error": "File not found"}), 404

    # Serve the PDF file securely
    return send_file(file_path, as_attachment=True, mimetype="application/zip")

@app.route('/tasks', methods=['POST'])
def tasks():
    # List of 7 valid tokens
    TOKEN_TO_TASKS = {
        "70c2df7f6d50809702c45ddf9e3400dafba4b6cd829a07bc72fdcc45539c49a8": [{"Reportes":"TRG-01","Funcionales_Seguridad":"TCG-01 y TCG-02","Específicos":"TCE-03"}],#challengeGR101
        "1bd0b578a3b018d5cb49b8abfe2b488d05a7f52ebdb69ab4b1d27e0d60378c57": [{"Reportes":"TRG-01","Funcionales_Seguridad":"TCG-01 y TCG-02","Específicos":"TCE-06"}],#challengeGR202
        "6a0b35dd21adab89e881a4b37e79b24382939ddf714407ec2d7321b130dd42fa": [{"Reportes":"TRG-01","Funcionales_Seguridad":"TCG-01 y TCG-02","Específicos":"TCE-04"}],#challengeGR303
        "0f2769d065cc97fa895df64a5d3526eae358d4746eb96e4f21809b89bd208028": [{"Reportes":"TRG-01","Funcionales_Seguridad":"TCG-01 y TCG-02","Específicos":"TCE-08"}],#challengeGR404
        "775b1e13bf83ea46abdef5b12b84a854f82da872867bae0066a2a509132141f6": [{"Reportes":"TRG-01","Funcionales_Seguridad":"TCG-01 y TCG-02","Específicos":"TCE-07"}],#challengeGR505
        "15ce9218029d6f229ac8238a1da94095c5f2684367e08ccb94ddddac15de2240": [{"Reportes":"TRG-01","Funcionales_Seguridad":"TCG-01 y TCG-02","Específicos":"TCE-05"}],#challengeGR606
        "765f659eb04b984ee6d9749763076db0e995c314ade24e93ed8c82d9b2dbbaf0": [{"Reportes":"TRG-01","Funcionales_Seguridad":"TCG-01 y TCG-02","Específicos":"TCE-08"}]#challengeGR707
    }
    
    """Endpoint to provide tasks if a valid token is given."""
    
    # Get the token from the request
    data = request.get_json(silent=True) or {}    
    token = str(data.get("token","")).strip()
    logging.info(token)

    # Validate token
    if token not in TOKEN_TO_TASKS:
        return jsonify({"error": "Invalid token"}), 404
    else:
        # Get the assigned tasks for the token
        logging.info(TOKEN_TO_TASKS[token]);
        return jsonify({"Tareas": TOKEN_TO_TASKS[token]}), 200              
   
    

@app.route('/448bfecc5dbab2abcd54748843095da8a7c4f8aacace7c73a55cea07de52d3b4', methods=['PUT'])
def tokenprovider():
    #{username_encoded}{password_encoded}{gr}{SALT}
    #GR1
        logging.info("Generating tokens")
        logging.info("GR1:"+hashlib.sha512("corey".encode()).hexdigest())
        logging.info("GR1:"+hashlib.sha512("unsainted".encode()).hexdigest())
        logging.info("GR1Token:"+hashlib.sha256(str(hashlib.sha512("corey".encode()).hexdigest()).encode()+
                                           str(hashlib.sha512("unsainted".encode()).hexdigest()).encode()+
                                           str("GR1").encode()+
                                           str(SALT).encode()).hexdigest())
    #GR3    
        logging.info("GR3:"+hashlib.sha512("davis".encode()).hexdigest())
        logging.info("GR3:"+hashlib.sha512("blind".encode()).hexdigest())
        logging.info("GR3Token:"+hashlib.sha256(str(hashlib.sha512("davis".encode()).hexdigest()).encode()+
                                           str(hashlib.sha512("blind".encode()).hexdigest()).encode()+
                                           str("GR3").encode()+
                                           str(SALT).encode()).hexdigest())
    
    #GR2
    # # Convert string to bytes
        byte_data_u = "eloy".encode("utf-8")
        byte_data_p = "waitandbleed".encode("utf-8")
        # Encode bytes to Base64
        logging.info("GR2:"+str(base64.b64encode(byte_data_u)))        
        logging.info("GR2:"+str(base64.b64encode(byte_data_p)))
        logging.info("GR2Token:"+hashlib.sha256(str(base64.b64encode(byte_data_u).decode("utf-8")).encode()+
                                           str(base64.b64encode(byte_data_p).decode("utf-8")).encode()+
                                           str("GR2").encode()+
                                           str(SALT).encode()).hexdigest())     
        
    #GR4    
        # Convert string to bytes
        byte_data_u = "fieldy".encode("utf-8")
        byte_data_p = "requiem".encode("utf-8")
        # Encode bytes to Base64
        logging.info("GR4:"+str(base64.b64encode(byte_data_u)))        
        logging.info("GR4:"+str(base64.b64encode(byte_data_p)))
        logging.info("GR4Token:"+hashlib.sha256(str(base64.b64encode(byte_data_u).decode("utf-8")).encode()+
                                           str(base64.b64encode(byte_data_p).decode("utf-8")).encode()+
                                           str("GR4").encode()+
                                           str(SALT).encode()).hexdigest())        
    #GR6
        # Convert string to bytes
        byte_data_u = "chester".encode("utf-8")
        byte_data_p = "intheend".encode("utf-8")
        # Encode bytes to Base64
        logging.info("GR6:"+str(base64.b64encode(byte_data_u)))        
        logging.info("GR6:"+str(base64.b64encode(byte_data_p)))
        logging.info("GR6Token:"+hashlib.sha256(str(base64.b64encode(byte_data_u).decode("utf-8")).encode()+
                                           str(base64.b64encode(byte_data_p).decode("utf-8")).encode()+
                                           str("GR6").encode()+
                                           str(SALT).encode()).hexdigest())        
    #GR5
        logging.info("GR5:"+hashlib.sha256("elliotalderson".encode()).hexdigest())
        logging.info("GR5:"+hashlib.sha256("fsociety".encode()).hexdigest())
        logging.info("GR5Token:"+hashlib.sha256(str(hashlib.sha256("elliotalderson".encode()).hexdigest()).encode()+
                                           str(hashlib.sha256("fsociety".encode()).hexdigest()).encode()+
                                           str("GR5").encode()+
                                           str(SALT).encode()).hexdigest())        
    #GR7
        logging.info("GR7:"+hashlib.sha256("kevinmitnick".encode()).hexdigest())
        logging.info("GR7:"+hashlib.sha256("pacificbell".encode()).hexdigest())
        logging.info("GR7Token:"+hashlib.sha256(str(hashlib.sha256("kevinmitnick".encode()).hexdigest()).encode()+
                                           str(hashlib.sha256("pacificbell".encode()).hexdigest()).encode()+
                                           str("GR7").encode()+
                                           str(SALT).encode()).hexdigest())   
        
        return jsonify({"info": "Done"}), 200    

if __name__ == '__main__':
    app.run()
