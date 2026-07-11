import os

def get_reset_link(token):
    trusted_host = os.environ.get('TRUSTED_HOST', 'tu-dominio-seguro.com')
    return f"https://{trusted_host}/reset?token={token}"