import type {NextConfig} from 'next';
import {resolve} from 'node:path';
const config:NextConfig={output:'standalone',turbopack:{root:resolve(__dirname,'../..')},async headers(){return [{source:'/:path*',headers:[{key:'X-Content-Type-Options',value:'nosniff'},{key:'X-Frame-Options',value:'DENY'},{key:'Strict-Transport-Security',value:'max-age=31536000'},{key:'Referrer-Policy',value:'same-origin'}]}];}};
export default config;
