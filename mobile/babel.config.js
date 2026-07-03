module.exports = function (api) {
  api.cache(true);
  return {
    presets: ['babel-preset-expo'],
    plugins: [
      // Hermes (the iOS/Android JS engine) does not support class private
      // properties/methods. babel-preset-expo normally transforms them, but
      // we force the transforms explicitly so the app never ships raw
      // `#field` syntax regardless of environment or preset detection.
      '@babel/plugin-transform-class-properties',
      '@babel/plugin-transform-private-methods',
      '@babel/plugin-transform-private-property-in-object',
    ],
  };
};
