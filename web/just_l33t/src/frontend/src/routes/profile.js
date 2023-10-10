import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import Navbar from "../components/navbar";
import { useTranslation } from 'react-i18next';
import { userinfo, orderInfo, isTosc } from "../utils/utils";

export default function Profile() {
    const { t, i18n } = useTranslation('');
    const [isLoaded, setIsLoaded] = useState(false)
    const navigate = useNavigate()
    const [userinformations, setUserInformations] = useState({})
    const [userOrders, setUserOrders] = useState(undefined)
    const [toscLang, setToscLang] = useState(false)

    const getinfo = async () => {
        var info = await userinfo()
        if (info.status !== 200) {
            navigate("/login")
            return
        }
        info = await info.json()
        setUserInformations(info)

        var ordersinfo = await orderInfo()
        if (ordersinfo.status !== 200) {
            navigate("/login")
            return
        }
        ordersinfo = await ordersinfo.json()
        setUserOrders(ordersinfo)
        setIsLoaded(true)
    }
    useEffect(() => {
        getinfo()
        if (isTosc(window.location.hostname)) {
            i18n.changeLanguage('tosc');
            setToscLang(true)
        } else {
            i18n.changeLanguage();
        }
    }, [])

    if (isLoaded) {
        return (
            // <div className="w-full min-h-screen h-full bg-slate-100 flex flex-col items-center justify-start content-center text-zinc-800">
            //     <Navbar />
            //     <div className="w-full flex flex-col items-center justify-center content-center min-h-screen h-full">
            //         <div className="overflow-auto flex flex-col items-center justify-between content-center h-2/3 w-3/4 h-full rounded-lg shadow border bg-slate-300 border-gray-300">
            //             <div className="flex flex-col items-center justify-start content-center w-full h-full">
            // <h1 className="pt-5 pb-1 text-xl font-bold border-b w-3/4 text-center text-4xl border-slate-700">
            //     {userinformations.username}
            // </h1>
            // <div id="order_container" className="my-4 h-full overflow-auto flex flex-col items-center justify-start content-center w-1/2 rounded-lg shadow border bg-orange-500/90 border-gray-300">
            //     <p className="text-2xl py-2 w-full border-b border-orange-900 text-center">{t('Your Orders:')}</p>
            //     {
            //         userOrders?.map((order, index) => {
            //             var style = "border-b border-orange-900"
            //             if (index === userOrders.length - 1) {
            //                 style = ""
            //             }
            //             return <div key={order.id} className={"flex overflow-auto flex-col items-start " + style + " justify-start content-center p-3 w-4/5"}>
            //                 <p className="font-bold">{t("Order number:")} {order.id}</p>
            //                 {
            //                     order.items.map(item => {
            //                         return <div key={item.item_id} className="flex items-center justify-start content-center p-3 w-full">
            //                             <p>•{(toscLang) ? item.name_to : item.name_en} x{item.quantity}: {item.quantity * item.price}$</p></div>
            //                     })}
            //             </div>
            //         }
            //         )
            //     }
            //                 </div>
            //             </div>
            //         </div>
            //     </div>
            // </div>
            <div className="w-full h-screen bg-slate-100 flex flex-col items-center justify-start content-center text-zinc-800">
                <Navbar />
                <div className="w-full flex flex-col items-center justify-center content-center h-full">
                    <div className="flex flex-col items-center justify-between content-center rounded-lg shadow border bg-slate-300 border-gray-300 w-2/3 h-3/4">
                        <div className="flex flex-col w-full items-center content-start justify-start">
                            <h1 className="pt-5 pb-1 text-xl font-bold border-b w-3/4 text-center text-4xl border-slate-700">
                                {userinformations.username}
                            </h1>
                            <div className="my-4 h-full flex flex-col items-center justify-start content-center w-1/2 rounded-lg shadow border bg-orange-500/90 border-orange-300">
                                <p className="text-2xl py-2 w-full border-b border-orange-900 text-center">{t('Your Orders:')}</p>
                                <div id="order_container" className="my-4 overflow-auto w-full h-96 flex flex-col items-center justify-start content-center">
                                    {
                                        userOrders?.map((order, index) => {
                                            var style = "border-b border-orange-900"
                                            if (index === userOrders.length - 1) {
                                                style = ""
                                            }
                                            return <div key={order.id} className={"flex flex-col items-start " + style + " justify-start content-center p-3 w-4/5"}>
                                                <p className="font-bold">{t("Order number:")} {order.id}</p>
                                                {
                                                    order.items.map(item => {
                                                        return <div key={item.item_id} className="flex items-center justify-start content-center p-3 w-full">
                                                            <p>•{(toscLang) ? item.name_to : item.name_en} x{item.quantity}: {item.quantity * item.price}$</p></div>
                                                    })}
                                            </div>
                                        }
                                        )
                                    }
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

        )
    } else {
        return (<div className="w-full h-screen bg-slate-100 flex flex-col items-center justify-start content-center text-zinc-800"><Navbar /></div>)
    }
}