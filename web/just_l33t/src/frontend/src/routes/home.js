import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import FoodCard from "../components/food_card";
import Navbar from "../components/navbar";
import { itemsInfo } from "../utils/utils";

export default function Home() {
    const navigate = useNavigate()
    const [isLoaded, setIsLoaded] = useState(false)
    const [items, setItems] = useState([])

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
    useEffect(() => {
        getItemsInfo()
    }, [])
    if (isLoaded) {
        return (
            <div className="w-full h-full bg-slate-100 flex flex-col items-center justify-start content-center text-zinc-800">
                <Navbar />
                <div className="flex flex-col items-center justify-center align-start w-3/4">
                    {
                    items.map(item=><FoodCard key={item.id} item={item} />)
                }
                </div>
            </div>)
    }else{
        return(<div className="w-full h-screen bg-slate-100 flex flex-col items-center justify-start content-center text-zinc-800"><Navbar /></div>)
    }
}