from flask import Flask, jsonify

# Inisialisasi Flask
app = Flask(__name__)
app.secret_key = "simple-key-for-testing"

# Route sederhana
@app.route('/')
def home():
    return jsonify({
        "status": "success",
        "message": "OXYX FORTRESS is running on Vercel!",
        "version": "1.0.0"
    })

@app.route('/health')
def health():
    return jsonify({"status": "healthy"})

@app.route('/test')
def test():
    return jsonify({"data": "test successful"})

# 🔴 PALING PENTING! Handler untuk Vercel
def handler(request):
    """Handler untuk Vercel serverless"""
    with app.request_context(request):
        return app.full_dispatch_request()

# Untuk testing local
if __name__ == '__main__':
    app.run(port=5000, debug=True)
