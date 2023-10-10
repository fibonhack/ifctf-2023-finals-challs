import { useEffect } from "react"
import image from "../images/image.jpg"
import { getCookieValue, isTosc } from "../utils/utils"
import { useState } from "react"
import { useTranslation } from "react-i18next"

export default function FoodCard(item) {
    const [toscLang,setToscLang]=useState(false) 
    const { t, i18n } = useTranslation('');

    item = item.item
    const cartLogic = async (e) => {
        let selected_item_id = parseInt(e.target.id);

        var cart = getCookieValue("cart");
        if (cart !== undefined) {
            cart = JSON.parse(atob(cart))
            var found = false

            cart.items.forEach(item=>{
                if (item.id === selected_item_id){
                    item.quantity = item.quantity +1
                    found = true
                }
            })
            if(!found){
                cart.items.push({
                    id: selected_item_id,
                    quantity: 1
                })
            }
            document.cookie = "cart=" + btoa(JSON.stringify(cart))
        } else {
            cart = {
                items:[{
                    id: selected_item_id,
                    quantity:1
                }],
                tip:0
            }
            document.cookie = "cart=" + btoa(JSON.stringify(cart))
        }
    }

    useEffect(()=>{
        if (isTosc(window.location.hostname)) {
            i18n.changeLanguage('tosc');
            setToscLang(true)
        } else {
            i18n.changeLanguage();
        }
    },[])

    return (
        <div className="w-2/3 flex items-start p-5 justify-start align-starttext-zinc-800">
            <img src={image} className="rounded-lg w-1/2" />
            <div className="flex flex-col items-start justify-between content-center px-3">
                <p id="object_name" className="text-xl font-bold">{(toscLang)? item.name_to : item.name_en}</p>
                <p id="object_price" className="text-lg">{item.price}$</p>
                <button type="submit" id={item.id} className="bg-orange-500 focus:bg-orange-400 hover:bg-orange-400 w-40 focus:outline-none font-medium rounded-lg px-5 py-2 text-center"
                    onClick={cartLogic}> {t('Add to Cart')}</button>
            </div>
        </div>)
}