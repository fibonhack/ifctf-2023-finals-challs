import { useState } from "react";
import { login } from "../utils/auth";
import { useNavigate } from "react-router-dom";

export default function Login() {
    const [error, setError] = useState("")
    const navigate = useNavigate()

    const login_submit = async (e) => {
        e.preventDefault();
        const json_response = await login(e.target.username.value, e.target.password.value);
        if (json_response.error !== undefined) {
            setError(json_response.error)
            return
        } else {
            localStorage.setItem("token", json_response.data.accessToken);
            navigate("/profile")
        }
    }
    return (
        <section className="bg-slate-900">
            <div className="flex flex-col items-center justify-center px-6 py-8 mx-auto md:h-screen lg:py-0">
                <div className="w-full rounded-lg shadow border md:mt-0 sm:max-w-md xl:p-0 bg-slate-800 border-gray-700">
                    <div className="p-6 space-y-4 md:space-y-6 sm:p-8">
                        <h1 className="text-xl font-bold leading-tight tracking-tight text-gray-900 md:text-2xl text-white">
                            Sign in to your account
                        </h1>
                        <form className="space-y-4 md:space-y-6"
                            onSubmit={login_submit}>
                            <div>
                                <input type="text" name="username" className="rounded-lg focus:outline-none block w-full p-2.5 bg-gray-700 border-gray-600 placeholder-gray-400 text-white focus:ring-blue-500 focus:border-blue-500" placeholder="Username" required />
                            </div>
                            <div>
                                <input type="password" name="password" placeholder="••••••••" className="rounded-lg focus:outline-none block w-full p-2.5 bg-gray-700 border-gray-600 placeholder-gray-400 text-white focus:ring-blue-500 focus:border-blue-500" required />
                            </div>
                            <button type="submit" className="bg-slate-700 focus:bg-slate-600 hover:bg-slate-600 w-full text-white focus:outline-none font-medium rounded-lg text-sm px-5 py-2.5 text-center ">Sign in</button>
                            <p className="text-sm font-light text-gray-500 text-rose-400">{error}</p>
                            <p className="text-sm font-light text-gray-500 text-gray-400">
                                Don’t have an account yet? <a href="register" className="font-medium text-primary-600 hover:underline text-primary-500">Sign up</a>
                            </p>
                        </form>
                    </div>
                </div>
            </div>
        </section>
    )
}