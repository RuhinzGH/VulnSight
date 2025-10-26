import { StrictMode } from "react";  //wrapper that highlights pootential problems in development early
import { createRoot } from "react-dom/client"; //modern React API to render app
import "./index.css";  //app wide css
import App from "./App.jsx";  //parent
import { UserProvider } from "./UserContext.jsx"; //make user data accessible to all components w/o prop drilling

const container = document.getElementById("root");  //connect React to html
const root = createRoot(container);  //object to manage rendering

root.render(  //render logic
  <StrictMode> 
    <UserProvider>
      <App />
    </UserProvider>
  </StrictMode>
);
//catch errors quickly; App in UserProvider so all components have access to user data
