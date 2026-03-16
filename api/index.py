from flask import Flask, jsonify, request

# Buat Flask app
app = Flask(__name__)

# Route utama
@app.route('/')
def home():
    return jsonify({
        'status': 'success',
        'message': 'OXYX FORTRESS is running!',
        'version': '1.0.0'
    })

# Route health check
@app.route('/health')
def health():
    return jsonify({'status': 'healthy'})

# 🔴 INI YANG PALING PENTING - HANDLER UNTUK VERCEL
def handler(request):
    """Handler untuk Vercel serverless function"""
    try:
        # Debug: cetak info request
        print(f"Request method: {request.method}")
        print(f"Request path: {request.path}")
        
        # Dispatch request ke Flask
        with app.request_context(request):
            response = app.full_dispatch_request()
            return response
    except Exception as e:
        # Tangkap error dan kembalikan response JSON
        print(f"Error: {str(e)}")
        return {
            'statusCode': 500,
            'body': jsonify({
                'error': str(e),
                'message': 'Internal Server Error'
            })
        }

# Untuk testing local
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
