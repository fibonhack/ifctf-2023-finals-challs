import { useEffect, useState } from "react";
import { createProperty, deletePropertyById, getProfileName, getProfileProperties } from "../utils/user-utils";
import { useNavigate } from "react-router-dom";

export default function Profile() {
    const navigate = useNavigate()
    const [error, setError] = useState("")
    const [username, setUsername] = useState("")
    const [properties, setProperties] = useState([])
    const [isLoaded, setIsLoaded] = useState(false)

    const getData = async () => {
        var user_data = await getProfileName()
        var properties_data = await getProfileProperties()
        if (user_data.status !== 200 || properties_data.status !== 200) {
            navigate("/")
            return
        }
        user_data = await user_data.json()
        setUsername(user_data.data.username)
        properties_data = await properties_data.json()
        setProperties(properties_data.data.properties)
        setIsLoaded(true)
    }

    const newProperty = async (e) => {
        e.preventDefault();
        var response = await createProperty(e.target.property_name.value, e.target.property_value.value)
        if (response.status !== 201) {
            setError((await response.json()).error)
            return
        } else {
            setError("")
        }
        e.target.reset()
        window.location.reload()
    }
    const deleteProperty = async (e) => {
        deletePropertyById(e.target.id)
        window.location.reload()
    }

    useEffect(() => {
        if (localStorage.getItem("token") === undefined) {
            navigate("/")
            return
        }
        getData()
    }, [])

    return (
        <section className="bg-slate-900 text-slate-200">
            <nav className="flex items-start align-canter justify-between bg-slate-800 w-full p-3 mb-2 border-b border-slate-500">
                <p className="mx-2 px-1 text-xl text-center border-r border-slate-200">{username}'s profile</p>
                <div>
                    <a href="/posts" className="hover:text-cyan-500 mx-2">Posts</a>
                    <a href="#" className="hover:text-cyan-500 mx-2">Properties</a>
                </div>
            </nav>
            {isLoaded ?
                <div className="flex flex-col w-full items-center justify-center px-6 py-8 mx-auto h-screen">
                    <div className="flex flex-col items-center justify-center align-center w-3/4 h-full rounded-lg shadow border bg-slate-800 border-gray-700 overflow-auto">
                        <p className="text-2xl my-2 border-b border-slate-500 w-3/4 text-center pb-2">Currently set properties:</p>
                        <div className="flex flex-col max-h-64 h-64 overflow-auto items-center justify-start align-center w-3/4 text-xl text-center py-2">{
                            properties.map(property => <div className="flex items-center justify-between align-center my-2 p-1 rounded-md w-2/3 shadow border bg-slate-700 border-gray-600">
                                {property.key}: {property.value} <button id={property.id} className="bg-rose-700 focus:bg-rose-600 hover:bg-rose-600 focus:outline-none font-medium rounded-lg text-sm px-5 py-2.5 text-center" onClick={deleteProperty}>delete</button> </div>)
                        }</div>
                        <div className="py-2 border-b border-slate-200"></div>
                        <p className="w-3/4 text-xl text-center py-2 my-2">Set a new property!</p>
                        <form className="space-y-4 md:space-y-6 w-1/3"
                            onSubmit={newProperty}>
                            <div>
                                <input type="text" name="property_name" placeholder="Property" className="rounded-lg focus:outline-none block w-full p-2.5 bg-gray-700 border-gray-600 placeholder-gray-400 text-white focus:ring-blue-500 focus:border-blue-500" required />
                            </div>
                            <div>
                                <input type="text" name="property_value" placeholder="Value" className="rounded-lg focus:outline-none block w-full p-2.5 bg-gray-700 border-gray-600 placeholder-gray-400 text-white focus:ring-blue-500 focus:border-blue-500" required />
                            </div>
                            <p className="text-sm font-light text-gray-500 text-rose-400">{error}</p>
                            <button type="submit" className="my-2 bg-slate-700 focus:bg-slate-600 hover:bg-slate-600 w-full text-white focus:outline-none font-medium rounded-lg text-sm px-5 py-2.5 text-center ">Submit</button>
                        </form>
                        <button className="my-2 bg-rose-700 focus:bg-rose-600 hover:bg-rose-600 w-1/3 text-white focus:outline-none font-medium rounded-lg text-sm px-5 py-2.5 text-center" onClick={() => {
                            localStorage.clear()
                            navigate("/")
                        }
                        }>Log out</button>
                    </div>
                </div>
                :
                <div className="bg-slate-900 text-slate-200 min-h-screen"></div>
            }
        </section>
    )
}