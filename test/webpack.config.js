const path = require('path');

module.exports = {
  entry: './openssl_wasm.ts',
  output: {
    filename: 'bundle.js',
    path: path.resolve(__dirname, 'test/public'),
    library: 'OpensslEVP',
    libraryTarget: 'window',
  },
  resolve: {
    extensions: ['.ts', '.js'],
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
  mode: 'development',
};
