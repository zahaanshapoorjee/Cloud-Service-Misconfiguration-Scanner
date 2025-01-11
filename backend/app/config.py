import os

class Config:
    AWS_REGION = os.getenv('AWS_DEFAULT_REGION', 'ap-south-1')