export const backend = "/api"

export async function login(username, password) {
    var response = await fetch(backend + "/login", {
        method: "POST",
        credentials: "include",
        headers: {
            "Content-Type": "application/json",
        },
        body: JSON.stringify({
            "username": username,
            "password": password
        })
    })

    return response
}

export async function register(username, password) {
    var response = await fetch(backend + "/register", {
        method: "POST",
        credentials: "include",
        headers: {
            "Content-Type": "application/json",
        },
        body: JSON.stringify({
            "username": username,
            "password": password
        })
    })
    return response
}

export async function userinfo() {
    var response = await fetch(backend + "/user", {
        method: "GET",
        credentials: "include"
    })
    return response
}

export async function itemsInfo() {
    var response = await fetch(backend + "/items", {
        method: "GET",
        credentials: "include",
    })
    return response
}

export async function orderInfo() {
    var response = await fetch(backend + "/order", {
        method: "GET",
        credentials: "include",
    })
    return response
}

export async function checkout(items) {
    var response = await fetch(backend + "/order", {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
        },
        credentials: "include",
        body: items
    })
    return response
}

export async function cookieBridge() {
    var lang = (isTosc(window.location.hostname))?"en":"to"
    window.location.href = "/api/cookie_bridge?to="+lang
}

export function getCookieValue(name) {
    const regex = new RegExp(`(^| )${name}=([^;]+)`)
    const match = document.cookie.match(regex)
    if (match) {
        return match[2]
    }
}

export function delete_cookie(name) {
    document.cookie = name + '=;expires=Thu, 01 Jan 1970 00:00:01 GMT;';
};

export function isTosc(input){
    if(input.match(/^\w+\./) && input.match(/^\w+\./)[0] === 'to.'){
        return true
    }
    return false
}