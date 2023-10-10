import { useState } from "react";
import { register } from "../utils/auth";
import { useNavigate } from "react-router-dom";

export default function Register() {
    const [error, setError] = useState("")
    const navigate = useNavigate()
    const register_submit = async (e) => {
        e.preventDefault();
        var username = e.target.username.value;
        var password = e.target.password.value;
        var password_confirm = e.target.password_confirm.value
        if (password !== password_confirm) {
            alert("passwords don't match")
            return
        }
        const response = await register(username, password);
        if (response.status !== 204) {
            const response_json = await response.json()
            setError(response_json.error)
        } else {
            navigate("/")
        }
    }
    return (
        <section className="bg-slate-900">
            <div className="flex flex-col items-center justify-center px-6 py-8 mx-auto md:h-screen lg:py-0">
                <div className="w-full rounded-lg shadow border md:mt-0 sm:max-w-md xl:p-0 bg-slate-800 border-gray-700">
                    <div className="p-6 space-y-4 md:space-y-6 sm:p-8">
                        <h1 className="text-xl font-bold leading-tight tracking-tight text-gray-900 md:text-2xl text-white">
                            Sign up now!
                        </h1>
                        <form className="space-y-4 md:space-y-6"
                            onSubmit={register_submit}>
                            <input type="text" name="username" className="rounded-lg focus:outline-none block w-full p-2.5 bg-gray-700 border-gray-600 placeholder-gray-400 text-white focus:ring-blue-500 focus:border-blue-500" placeholder="Username" required />
                            <input type="password" name="password" placeholder="Password" className="rounded-lg focus:outline-none block w-full p-2.5 bg-gray-700 border-gray-600 placeholder-gray-400 text-white focus:ring-blue-500 focus:border-blue-500" required />
                            <input type="password" name="password_confirm" placeholder="Confirm Password" className="rounded-lg focus:outline-none block w-full p-2.5 bg-gray-700 border-gray-600 placeholder-gray-400 text-white focus:ring-blue-500 focus:border-blue-500" required />
                            <p className="text-sm font-light text-gray-500 text-rose-400">{error}</p>
                            <button type="submit" className="bg-slate-700 focus:bg-slate-600 hover:bg-slate-600 w-full text-white focus:outline-none font-medium rounded-lg text-sm px-5 py-2.5 text-center ">Sign in</button>
                        </form>
                    </div>
                </div>
            </div>
        </section>
    )
}