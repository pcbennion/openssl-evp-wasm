const path = require('path');

module.exports = {
  entry: './opensslWorker.ts',
  output: {
    filename: 'bundle.js',
    path: path.resolve(__dirname, 'public'),
    library: {
      type: 'module',
    }
  },
  resolve: {
    extensions: ['.ts', '.js'],
  },
  experiments: {
    outputModule: true,
    asyncWebAssembly: true,
  },
  externals: {
    'openssl_wasm': 'Module'
  },
  module: {
    rules: [
      {
        test: /\.ts$/,
        use: 'ts-loader',
        exclude: /node_modules/,
      },
    ],
  },
  mode: 'production',
};
