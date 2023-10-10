import './App.css';
import { BrowserRouter, Routes, Route } from "react-router-dom";
import Login from './routes/login';
import Register from './routes/register';
import Profile from './routes/profile';
import Posts from './routes/posts';

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path='/' element={<Login />} />
        <Route path='/register' element={<Register />} />
        <Route path='/profile' element={<Profile />} />
        <Route path='/posts' element={<Posts />} />
      </Routes>
    </BrowserRouter>

  );
}