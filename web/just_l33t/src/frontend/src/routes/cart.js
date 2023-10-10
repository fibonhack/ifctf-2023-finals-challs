import { useEffect, useState } from "react";
import Navbar from "../components/navbar";
import { getCookieValue, itemsInfo, checkout, delete_cookie, isTosc } from "../utils/utils";
import image from "../images/image.jpg"
import { useNavigate } from "react-router-dom";
import { useTranslation } from 'react-i18next';

export default function Cart() {
    const [cart, setCart] = useState(undefined)
    const [isLoaded, setIsLoaded] = useState({})
    const [items, setItems] = useState([])
    const navigate = useNavigate()
    const [error, setError] = useState("")
    // translation
    const { t, i18n } = useTranslation();
    const [toscLang,setToscLang] = useState(false)

    const getItemsInfo = async () => {
        var response = await itemsInfo()
        if (response.status !== 200) {
            navigate("/login")
            return
        }
        response = await response.json()
        setItems(response)
        setIsLoaded(true)
    }

    const completeOrder = async () => {
        var cookie_cart = JSON.parse(atob(getCookieValue("cart")))
        const tip = parseFloat(document.getElementById("tip").value) || 0;
        cookie_cart.tip = tip

        var response = await checkout(JSON.stringify(cookie_cart))

        if (response.status !== 201) {
            response = await response.json()
            setError(response.error)
        } else {
            delete_cookie("cart")
            navigate("/profile")
        }
    }

    useEffect(() => {
        getItemsInfo()
        var cookie_cart = getCookieValue("cart");
        if (cookie_cart !== undefined) {
            cookie_cart = JSON.parse(atob(cookie_cart))
        }
        setCart(cookie_cart)
        // translation
        if (isTosc(window.location.hostname)) {
            i18n.changeLanguage('tosc');
            setToscLang(true)
        } else {
            i18n.changeLanguage();
        }

        setIsLoaded(true)
    }, [])

    if (isLoaded) {
        return (
            <div className="w-full h-screen bg-slate-100 flex flex-col items-center justify-start content-center text-zinc-800">
                <Navbar />
                <div className="w-full flex flex-col items-center justify-center content-center h-full">
                    <div className="flex flex-col items-center justify-between content-center rounded-lg shadow border bg-slate-300 border-gray-300 w-2/3 h-3/4">
                        <div className="flex flex-col w-full items-center content-start justify-start">
                            <p className="text-2xl py-2 w-3/4 border-b border-slate-700 text-center">{ t('Your Cart') }:</p>
                            <div className="overflow-auto flex flex-col items-center content-start justify-start">
                                {
                                    cart?.items.map(item =>
                                        <div key={item.id} className="flex items-center justify-start content-center p-3 w-3/4">
                                            <img src={image} className="w-1/4 rounded-lg" />
                                            <div className="flex flex-col items-start justify-start align-start h-full px-2 text-lg">
                                                <span id={item.id}>
                                                    {
                                                        items.forEach(retrieved => {
                                                            if (retrieved.id === parseInt(item.id)) {
                                                                var name = ''
                                                                if (toscLang){
                                                                    name = retrieved.name_to
                                                                }else{
                                                                    name = retrieved.name_en
                                                                }
                                                                document.getElementById(item.id).textContent = name
                                                                return
                                                            }
                                                        })
                                                    }
                                                </span>
                                                <p id="object_price">{t('number of items:')} {item.quantity}</p>
                                            </div>
                                        </div>)
                                }
                            </div>
                        </div>

                        <div className="flex flex-col items-center justify-center w-full">
                            {cart !== undefined ?
                                <div className="flex items-start content-center justify-start w-3/4 p-3">
                                    <labe className="px-2">Tip:</labe>
                                    <input id="tip" type="number" min="0" max="1" step="0.1" placeholder="0" required className="bg-slate-400 border-slate-200 rounded-lg p-2 placeholder-black/70 text-center" />
                                </div>
                                : <></>
                            }
                            <p className="text-sm font-light text-gray-500 text-rose-700">{error}</p>
                            <button className="bg-orange-500 focus:bg-orange-400 hover:bg-orange-400 w-1/2 focus:outline-none rounded-lg px-5 py-2.5 my-5 text-center"
                                onClick={completeOrder}>{t('Complete your order')}</button>
                        </div>
                    </div>
                </div>
            </div>)
    }
}