import { useEffect, useState } from "react";
import { createPost, getPosts, getProfileName, deleteProfilePost } from "../utils/user-utils";
import { useNavigate } from "react-router-dom";
// syntax highlighting
import Prism from "prismjs";
import Editor from 'react-simple-code-editor';
import 'prismjs/themes/prism.css';
import '../custom_highlight/custom_template.css';
import { FaTrash } from 'react-icons/fa';

Prism.languages.customlanguage = {
    'variable': /\[\[(.*?)\]\]/g,
};

export default function Posts() {
    const navigate = useNavigate()
    const [error, setError] = useState("")
    const [username, setUsername] = useState("")
    const [posts, setPosts] = useState([])
    const [isLoaded, setIsLoaded] = useState(false)
    const [code, setCode] = useState("");

    const getData = async () => {
        var user_data = await getProfileName()
        var posts_data = await getPosts()
        if (user_data.status !== 200 || posts_data.status !== 200) {
            navigate("/")
            return
        }
        user_data = await user_data.json()
        setUsername(user_data.data.username)
        posts_data = await posts_data.json()
        setPosts(posts_data.data.posts)
        setIsLoaded(true)
    }

    const newPost = async (e) => {
        e.preventDefault();
        var response = await createPost(e.target.post_content.value)
        if (response.status !== 201) {
            setError((await response.json()).error)
            return
        } else {
            setError("")
        }
        e.target.reset()
        window.location.reload()

    }
    const deletePost = async (e) => {
        console.log(e.target)
        var response = await deleteProfilePost(e.target.id)
        if (response.status !== 200) {
            setError((await response.json()).error)
            return
        } else {
            setError("")
        }
        window.location.reload()
    }

    useEffect(() => {
        if (localStorage.getItem("token") === undefined) {
            navigate("/")
            return
        }
        getData()
        Prism.highlightAll();
    }, [])

    return (
        <section className="bg-slate-900 text-slate-200">
            <nav className="flex items-start align-canter justify-between bg-slate-800 w-full p-3 mb-2 border-b border-slate-500">
                <p className="mx-2 px-1 text-xl text-center border-r border-slate-200">{username}'s profile</p>
                <div>
                    <a href="#" className="hover:text-cyan-500 mx-2">Posts</a>
                    <a href="/profile" className="hover:text-cyan-500 mx-2">Properties</a>
                </div>
            </nav>
            {isLoaded ?
                <div className="flex flex-col w-full items-center justify-center px-6 py-8 mx-auto h-screen">
                    <div className="flex flex-col items-center justify-center align-center w-3/4 h-full rounded-lg shadow border bg-slate-800 border-gray-700 overflow-auto">
                        <p className="text-2xl my-2 border-b border-slate-500 w-3/4 text-center pb-2">Posts</p>
                        <div className="flex flex-col max-h-96 min-h-96 h-96 overflow-auto items-center justify-start align-center w-3/4 text-xl text-center py-2">{
                            posts.map(post => <div className="w-full flex items-center justify-center align-center ">
                                <div className="overflow-auto flex items-center justify-between align-center m-2 p-1 rounded-md w-2/3 shadow border bg-slate-700 border-gray-600">
                                    {post.content}
                                </div>
                                <button id={post.id} className="rounded-lg py-1 px-2 bg-rose-800 hover:bg-rose-700 focus:bg-rose-700" onClick={deletePost}>
                                    delete
                                </button>
                            </div>)
                        }</div>
                        <div className="py-2 border-b border-slate-200"></div>
                        <p className="w-3/4 text-xl text-center py-2 my-2">Write new post</p>
                        <form className="flex flex-col items-center justify-center align-center space-y-4 md:space-y-6 w-2/3"
                            onSubmit={newPost}>
                            <div className="custom-language-editor">
                                <Editor
                                    value={code}
                                    name="post_content"
                                    placeholder="..."
                                    className="rounded-md focus:outline-none h-48 block w-full p-2.5 bg-gray-700 border-gray-600 placeholder-gray-400"
                                    onValueChange={(newCode) => setCode(newCode)}
                                    highlight={(code) => Prism.highlight(code, Prism.languages.customlanguage, 'customlanguage')}
                                    padding={10}
                                    style={{
                                        fontFamily: '"Fira code", "Fira Mono", monospace',
                                        fontSize: 14,
                                    }}
                                />
                            </div>
                            <p className="text-sm font-light text-gray-500 text-rose-400">{error}</p>
                            <button type="submit" className="w-3/4 my-2 bg-slate-700 focus:bg-slate-600 hover:bg-slate-600 text-white focus:outline-none font-medium rounded-lg text-sm px-5 py-2.5 text-center ">Submit</button>
                        </form>
                    </div>
                </div>
                :
                <div className="bg-slate-900 text-slate-200 min-h-screen"></div>
            }
        </section>
    )
}