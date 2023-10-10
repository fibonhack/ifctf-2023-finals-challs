import { useEffect, useState } from "react";
import icon from "../images/icon.png"
import { useTranslation } from 'react-i18next';
import { isTosc, userinfo, cookieBridge} from "../utils/utils";

export default function Navbar() {
    const { t, i18n } = useTranslation('');
    const [isLogged, setIsLogged] = useState(false)
    const [isAdmin, setIsAdmin] = useState(false)

    const checkLogin = async () => {
        var info = await userinfo()
        if (info.status === 200) {
            setIsLogged(true)
            info = await info.json()

            if (info.is_admin) {
                setIsAdmin(true)
            }
        }
    }


    const changeLang = () => {
        cookieBridge()
    }

    useEffect(() => {
        checkLogin()
        if (isTosc(window.location.hostname)) {
            i18n.changeLanguage('tosc');
        } else {
            i18n.changeLanguage();
        }
    }, [])

    return (
        <nav className="w-full flex justify-between items-center content-center py-5 px-20 bg-slate-300 shadow-md shadow-black/20 text-lg">
            <a href="/" className="hover:decoration-none"><img src={icon} alt="icon" className="w-1/3 rounded-lg"></img></a>
            <div className="flex items-center justify-center content-center">
                {isLogged ?
                    <>
                        <a id="cart_button" href="../cart" className="text-orange-500 hover:text-orange-400 px-2">{t('Cart')}</a>
                        <a href="../profile" className="text-orange-500 hover:text-orange-400 px-2">{t('Profile')}</a>
                    </> : <>
                        <a href="../login" className="text-orange-500 hover:text-orange-400 px-2">{t('Login')}</a>
                        <a href="../register" className="text-orange-500 hover:text-orange-400 px-2">{t('Register')}</a>
                    </>
                }
                {isAdmin ?
                    <>
                        <a id="admin_button" href="/api/cookie_bridge?to=admin" className="text-orange-500 hover:text-orange-400 px-2">{t('Go to admin')}</a>
                    </> : <></>
                }
                <button className="bg-orange-500 focus:bg-orange-400 hover:bg-orange-400 focus:outline-none font-medium rounded-lg px-5 py-2.5 text-center my-2"
                    onClick={changeLang}>{t('Change Language')} </button>
            </div>
        </nav>
    )
}