import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';
import { installApiAuth } from './lib/apiAuth';

// Attach the API key (if the server requires one) to every /api request before the app starts
installApiAuth();

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
