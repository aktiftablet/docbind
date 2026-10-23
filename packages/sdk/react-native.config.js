module.exports = {
  dependency: {
    platforms: {
      ios: { podspecPath: __dirname + '/DocBind.podspec' },
      android: {
        sourceDir: __dirname + '/native/android',
        packageImportPath: 'import com.securedoc.docbind.DocBindPackage;',
        packageInstance: 'new DocBindPackage()',
      },
    },
  },
};
