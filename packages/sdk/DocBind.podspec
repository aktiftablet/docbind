require 'json'
package = JSON.parse(File.read(File.join(__dir__, 'package.json')))
Pod::Spec.new do |s|
  s.name = 'DocBind'
  s.version = package['version']
  s.summary = package['description']
  s.homepage = 'https://github.com/aktiftablet/docbind'
  s.license = { :type => 'MIT' }
  s.author = 'DocBind'
  s.source = { :git => 'https://github.com/aktiftablet/docbind.git', :tag => s.version.to_s }
  s.platform = :ios, '13.0'
  s.swift_version = '5.0'
  s.source_files = 'native/ios/**/*.{swift,m,h}'
  s.dependency 'React-Core'
end
