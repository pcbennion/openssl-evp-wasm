const path = require('path');

module.exports = {
  context: path.resolve(__dirname, 'es6module'),
  entry: './openssl.ts',
  output: {
    filename: 'bundle.js',
    path: path.resolve(__dirname, 'es6module/public'),
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
        use: {
          loader: 'ts-loader',
          options: {
            configFile: path.resolve(__dirname, 'tsconfig.es6.json')
          }
        },
        exclude: /node_modules/,
      },
    ],
  },
  mode: 'production',
};
