import os

class Config:
    # MongoDB Configuration
    MONGODB_URI = os.getenv('MONGODB_URI', 'mongodb://localhost:27017/')
    SOURCE_COLLECTION = os.getenv('SOURCE_COLLECTION', 'raw_data')
    DESTINATION_COLLECTION = os.getenv('DESTINATION_COLLECTION', 'processed_data')
    DEAD_LETTER_COLLECTION = os.getenv('DEAD_LETTER_COLLECTION', 'failed_data')
    
    # Processing Configuration
    BATCH_SIZE = int(os.getenv('BATCH_SIZE', 10))
    PROCESSING_INTERVAL = int(os.getenv('PROCESSING_INTERVAL', 5))
    MAX_RETRIES = int(os.getenv('MAX_RETRIES', 3))
    RETRY_DELAY = int(os.getenv('RETRY_DELAY', 2))

    # Scan delivery (optional). When GATEWAY_URL is set, each document is a device scan
    # from the scanner server and is delivered to the API gateway with this token.
    GATEWAY_URL = os.getenv('GATEWAY_URL')
    INTERNAL_API_TOKEN = os.getenv('INTERNAL_API_TOKEN')
