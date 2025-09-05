const path = require('path');

module.exports = {
  entry: './opensslts',
  output: {
    filename: 'bundle.js',
    path: path.resolve(__dirname, 'public'),
    library: 'OpensslEVP',
    libraryTarget: 'window',
    libraryExport: 'default'
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
