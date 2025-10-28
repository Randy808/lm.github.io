export class LiquidSDK {
  async getConfidentialAddress() {
    return 'lq1qq2xm4gk5hl6qvyufwmxz8l9tdskz3r8fmmjvkqawmpl2r5q8zsw9yrmnm3q5l';
  }

  async getMessages() {
    return {
      'lq1qq2xm4gk5hl6qvyufwmxz8l9tdskz3r8fmmjvkqawmpl2r5q8zsw9yrmnm3q5l': [
        {
          message: 'Hello from Alice!',
          confirmation_time: 1729551901,
          explorer_url: 'https://blockstream.info/liquid/tx/example123',
          is_mine: false
        },
        {
          message: 'How are you doing?',
          confirmation_time: 1729551975,
          explorer_url: 'https://blockstream.info/liquid/tx/example456',
          is_mine: false
        }
      ],
      'lq1qqf8adstmkxhz8spr68y6k8xvyt5y2edwxrfqmhf8zc3uvjn2yfk9xqwxcl3d': [
        {
          message: 'Hey there!',
          confirmation_time: 1729548645,
          explorer_url: 'https://blockstream.info/liquid/tx/example789',
          is_mine: false
        }
      ]
    };
  }

  async getBalance() {
    return 25000;
  }

  async sendMessage(publicKey, message) {
    console.log(`Sending message to ${publicKey}: ${message}`);
    return {
      success: true,
      txid: 'mock_transaction_id',
      timestamp: new Date().toISOString()
    };
  }
}
