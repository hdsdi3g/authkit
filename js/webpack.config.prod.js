var path = require('path');

const CompressionPlugin = require("compression-webpack-plugin");
const TerserPlugin = require('terser-webpack-plugin');
const LicenseCheckerWebpackPlugin = require("license-checker-webpack-plugin");

module.exports = {
    entry: './src/app.js',
    cache: true,
    mode: 'production',
    plugins: [new CompressionPlugin({
        minRatio: 0.99,
        deleteOriginalAssets: true,
        exclude: ["../THIRD-PARTY-JS.txt"],
    }), new LicenseCheckerWebpackPlugin({
        outputFilename: "../THIRD-PARTY-JS.txt",
    })],
    optimization: {
        minimizer: [new TerserPlugin({
            extractComments: false,
        })],
    },
    output: {
        path: __dirname,
        filename: '../src/main/resources/static-generated/bundle.js'
    },
    module: {
        rules: [{
                test: path.join(__dirname, '.'),
                exclude: /(node_modules)/,
                use: [{
                    loader: 'babel-loader',
                    options: {
                        presets: ["@babel/preset-env", "@babel/preset-react"]
                    }
                }]
            }
        ]
    }
};