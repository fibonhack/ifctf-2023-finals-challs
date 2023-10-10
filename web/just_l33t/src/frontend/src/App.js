import { BrowserRouter, Routes, Route } from "react-router-dom";
import './App.css';
import Login from './routes/login';
import Register from './routes/register';
import Home from './routes/home';
import Profile from "./routes/profile";
import Cart from "./routes/cart";

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path='/' element={<Home />} />
        <Route path='/login' element={<Login />} />
        <Route path='/register' element={<Register />} />
        <Route path='/cart' element={<Cart />} />
        <Route path='/profile' element={<Profile />} />
      </Routes>
    </BrowserRouter>

  );
}

