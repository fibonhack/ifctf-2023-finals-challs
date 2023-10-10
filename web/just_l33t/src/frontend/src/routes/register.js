import { useState,useEffect } from "react";
import { register, isTosc } from "../utils/utils";
import { useNavigate } from "react-router-dom";
import Navbar from "../components/navbar";
import { useTranslation } from 'react-i18next';

export default function Register() {
    const [error, setError] = useState("")
    const navigate = useNavigate()
    const { t, i18n } = useTranslation('');

    const register_submit = async (e) => {
        e.preventDefault();
        const response = await register(e.target.username.value, e.target.password.value);
        if (response.status !== 201) {
            var json_response = await response.json()
            setError(json_response.error)
            return
        } else {
            navigate("/login")
        }
    }

    useEffect(()=>{
        if(isTosc(window.location.hostname)){
            i18n.changeLanguage('tosc');
        }else{
            i18n.changeLanguage();
        }
    },[])

    return (
        <div className="w-full h-screen bg-slate-100 flex flex-col items-center justify-start content-center text-zinc-800">
            <Navbar />
            <div className="flex w-full flex-col items-center justify-center h-full px-6 py-8">
                <div className="w-1/2 rounded-lg shadow border bg-slate-300 border-gray-300">
                    <div className="p-6 space-y-4 w-full">
                        <h1 className="text-xl font-bold">
                            {t('Sign up')}
                        </h1>
                        <form className="space-y-6"
                            onSubmit={register_submit}>
                            <div>
                                <input type="text" name="username" className="rounded-lg block w-full p-2.5 bg-slate-300 border border-black placeholder-slate-700 " placeholder="Username" required />
                            </div>
                            <div>
                                <input type="password" name="password" placeholder="••••••••" className="rounded-lg focus:outline-none block w-full p-2.5 bg-slate-300 border border-black placeholder-slate-700" required />
                            </div>
                            <button type="submit" className="bg-orange-500 focus:bg-orange-400 hover:bg-orange-400 w-full focus:outline-none font-medium rounded-lg text-sm px-5 py-2.5 text-center ">{t('Sign up')}</button>
                            <p className="text-sm font-light text-gray-500 text-rose-700">{error}</p>
                        </form>
                    </div>
                </div>
            </div>
        </div>
    )
}