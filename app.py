import os
from flask import Flask, render_template, request, redirect, url_for
import shift_cipher
import hill_cipher
import playfair_cipher
import primitive_root
import aes
import des_single

base_dir = os.path.abspath(os.path.dirname(__file__))
template_dir = os.path.join(base_dir, 'templates')
static_dir = os.path.join(base_dir, 'static')

app = Flask(__name__, 
            template_folder=template_dir, 
            static_folder=static_dir)

# --- Navigation Routes ---

@app.route('/')
def root():
    return redirect(url_for('exercise', ex_id='ex1'))

@app.route('/<ex_id>')
def exercise(ex_id):
    valid_ex = ['ex1', 'ex2']
    if ex_id not in valid_ex:
        return redirect(url_for('exercise', ex_id='ex1'))
    return render_template('index.html', active_ex=ex_id)

# --- Shift Cipher Routes ---

@app.route('/shift_encrypt.html', methods=['GET', 'POST'])
def shift_encrypt_route():
    result, error = None, None
    if request.method == 'POST':
        try:
            result = shift_cipher.encrypt_shift(request.form.get('plaintext', ''), request.form.get('key', ''))
        except Exception as e: error = str(e)
    return render_template('shift_encrypt.html', result=result, error=error)

@app.route('/shift_decrypt.html', methods=['GET', 'POST'])
def shift_decrypt_route():
    result, error = None, None
    if request.method == 'POST':
        try:
            result = shift_cipher.decrypt_shift(request.form.get('ciphertext', ''), request.form.get('key', ''))
        except Exception as e: error = str(e)
    return render_template('shift_decrypt.html', result=result, error=error)

# --- Hill Cipher Routes ---

@app.route('/hill_encrypt.html', methods=['GET', 'POST'])
def hill_encrypt_route():
    result_data, error = None, None
    if request.method == 'POST':
        try:
            size = request.form.get('size', '')
            key_input = request.form.get('key', '')
            pt = request.form.get('plaintext')
            matrix = hill_cipher.parse_square_matrix(key_input, size if size != '' else None)
            result_data = hill_cipher.encrypt_hill(pt, matrix)
        except Exception as e: error = str(e)
    return render_template('hill_encrypt.html', data=result_data, error=error)

@app.route('/hill_decrypt.html', methods=['GET', 'POST'])
def hill_decrypt_route():
    result_data, error = None, None
    if request.method == 'POST':
        try:
            size = request.form.get('size', '')
            key_input = request.form.get('key', '')
            ct = request.form.get('ciphertext')
            matrix = hill_cipher.parse_square_matrix(key_input, size if size != '' else None)
            result_data = hill_cipher.decrypt_hill(ct, matrix)
        except Exception as e: error = str(e)
    return render_template('hill_decrypt.html', data=result_data, error=error)

# --- Hill Math Tool Routes ---

@app.route('/hill_determinant.html', methods=['GET', 'POST'])
def hill_determinant_route():
    det, det_mod, error = None, None, None
    if request.method == 'POST':
        try:
            matrix = hill_cipher.parse_square_matrix(request.form.get('matrix'), request.form.get('size'))
            d = hill_cipher.determinant(matrix)
            det, det_mod = d, hill_cipher.mod(d)
        except Exception as e: error = str(e)
    return render_template('hill_determinant.html', det=det, det_mod=det_mod, error=error)

@app.route('/hill_cofactor.html', methods=['GET', 'POST'])
def hill_cofactor_route():
    result, error = None, None
    if request.method == 'POST':
        try:
            matrix = hill_cipher.parse_square_matrix(request.form.get('matrix'), request.form.get('size'))
            cof = hill_cipher.cofactor_matrix(matrix)
            result = "\n".join(" ".join(str(x) for x in row) for row in cof)
        except Exception as e: error = str(e)
    return render_template('hill_cofactor.html', result=result, error=error)

@app.route('/hill_transpose.html', methods=['GET', 'POST'])
def hill_transpose_route():
    result, error = None, None
    if request.method == 'POST':
        try:
            matrix = hill_cipher.parse_square_matrix(request.form.get('matrix'), request.form.get('size'))
            trans = hill_cipher.transpose(matrix)
            result = "\n".join(" ".join(str(x) for x in row) for row in trans)
        except Exception as e: error = str(e)
    return render_template('hill_transpose.html', result=result, error=error)

@app.route('/hill_matrix_inverse.html', methods=['GET', 'POST'])
def hill_matrix_inverse_route():
    det, det_mod, det_inv, cofactor, inverse, error = None, None, None, None, None, None
    if request.method == 'POST':
        try:
            matrix = hill_cipher.parse_square_matrix(request.form.get('matrix'), request.form.get('size'))
            det = hill_cipher.determinant(matrix)
            det_mod = hill_cipher.mod(det)
            cof = hill_cipher.cofactor_matrix(matrix)
            cofactor = "\n".join(" ".join(str(x) for x in row) for row in cof)
            try:
                det_inv = hill_cipher.mod_inverse(det_mod)
                inv_m = hill_cipher.inverse_matrix_mod26(matrix)
                inverse = "\n".join(" ".join(str(x) for x in row) for row in inv_m)
            except:
                det_inv = "No Inverse"
                inverse = "Matrix is not invertible mod 26"
        except Exception as e: error = str(e)
    return render_template('hill_matrix_inverse.html', det=det, det_mod=det_mod, 
                           det_inv=det_inv, cofactor=cofactor, inverse=inverse, error=error)

@app.route('/hill_multiplicative_inverse.html', methods=['GET', 'POST'])
def hill_multiplicative_inverse_route():
    gcd_val, inverse, error = None, None, None
    if request.method == 'POST':
        try:
            a = int(request.form.get('a'))
            g, x = hill_cipher.extended_gcd(a, 26)
            gcd_val = g
            inverse = hill_cipher.mod(x, 26) if g == 1 else "No Inverse"
        except Exception as e: error = str(e)
    return render_template('hill_multiplicative_inverse.html', gcd=gcd_val, inverse=inverse, error=error)

# --- Playfair Cipher Routes ---

@app.route('/playfair_encrypt.html', methods=['GET', 'POST'])
def playfair_encrypt_route():
    result_data, error = None, None
    if request.method == 'POST':
        try:
            result_data = playfair_cipher.playfair_process(request.form.get('plaintext', ''), request.form.get('key', ''), 'encrypt')
        except Exception as e: error = str(e)
    return render_template('playfair_encrypt.html', data=result_data, error=error)

@app.route('/playfair_decrypt.html', methods=['GET', 'POST'])
def playfair_decrypt_route():
    result_data, error = None, None
    if request.method == 'POST':
        try:
            result_data = playfair_cipher.playfair_process(request.form.get('ciphertext', ''), request.form.get('key', ''), 'decrypt')
        except Exception as e: error = str(e)
    return render_template('playfair_decrypt.html', data=result_data, error=error)

# --- Primitive Root Routes ---

@app.route('/primitive_root.html', methods=['GET', 'POST'])
def primitive_root_route():
    result, error = None, None
    if request.method == 'POST':
        try:
            result = primitive_root.get_primitive_roots_info(int(request.form.get('modulus', '')), show_steps=True)
        except Exception as e: error = str(e)
    return render_template('primitive_root.html', result=result, error=error)

# --- AES & DES Routes (Ex2) ---

@app.route('/aes.html', methods=['GET', 'POST'])
def aes_route():
    result, error = None, None
    if request.method == 'POST':
        try:
            result = aes.compute_aes_trace(
                request.form.get('text', ''), 
                request.form.get('key', ''), 
                mode=request.form.get('mode', 'ECB'), 
                operation=request.form.get('operation', 'ENCRYPT')
            )
        except Exception as e: error = str(e)
    return render_template('aes.html', result=result, error=error)

@app.route('/des.html', methods=['GET', 'POST'])
def des_route():
    result, error = None, None
    if request.method == 'POST':
        try:
            result = des_single.compute_des_trace(
                request.form.get('text', ''), 
                request.form.get('key', ''), 
                mode=request.form.get('mode', 'ECB'), 
                operation=request.form.get('operation', 'ENCRYPT')
            )
        except Exception as e: error = str(e)
    return render_template('des.html', result=result, error=error)

if __name__ == "__main__":
    # Render provides a PORT environment variable. We must use it.
    port = int(os.environ.get("PORT", 10000))
    # '0.0.0.0' is required to make the server reachable externally
    app.run(host="0.0.0.0", port=port)
