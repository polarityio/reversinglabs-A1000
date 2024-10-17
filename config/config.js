module.exports = {
  name: 'ReversingLabs A1000',
  acronym: 'A1000',
  defaultColor: 'light-pink',
  logging: { level: 'info' },
  entityTypes: ['MD5', 'SHA1', 'SHA256'],
  description: 'ReversingLabs A1000 integration for real-time file hash lookups',
  styles: ['./styles/a1000.less', './styles/exfoliate.less'],
  block: {
    component: {
      file: './component/block.js'
    },
    template: {
      file: './template/block.hbs'
    }
  },

  request: {
    // Provide the path to your certFile. Leave an empty string to ignore this option.
    // Relative paths are relative to the VT integration's root directory
    cert: '',
    // Provide the path to your private key. Leave an empty string to ignore this option.
    // Relative paths are relative to the VT integration's root directory
    key: '',
    // Provide the key passphrase if required.  Leave an empty string to ignore this option.
    // Relative paths are relative to the VT integration's root directory
    passphrase: '',
    // Provide the Certificate Authority. Leave an empty string to ignore this option.
    // Relative paths are relative to the VT integration's root directory
    ca: '',
    // An HTTP proxy to be used. Supports proxy Auth with Basic Auth, identical to support for
    // the url parameter (by embedding the auth info in the uri)
    proxy: ''
  },
  options: [
    {
      key: 'url',
      name: 'A1000 Server',
      description: 'A1000 Server',
      default: '',
      type: 'text',
      userCanEdit: false,
      adminOnly: false
    },
    {
      key: 'username',
      name: 'Username',
      description: 'ReversingLabs A1000 API Username',
      default: '',
      type: 'text',
      userCanEdit: false,
      adminOnly: false
    },
    {
      key: 'password',
      name: 'Password',
      description: 'ReversingLabs A1000 password',
      default: '',
      type: 'password',
      userCanEdit: false,
      adminOnly: false
    }
  ]
};
