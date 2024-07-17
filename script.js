let sites = [];

async function load_sites() {
    try {
        const response = await fetch("http://127.0.0.1:8080/load_websites");
        sites = await response.json();
        render_sites(sites);
    } catch (error) {
        console.error("Error loading sites:", error);
    }
}

function render_sites(sites) {
    const siteList = document.getElementById("site-list");
    siteList.innerHTML = ""; // Clear the list before rendering
    sites.forEach(site => {
        const li = document.createElement("li");
        li.className = "element";
        li.innerHTML = `
            ${site}
            <button class="button" onclick="remove_site('${site}')">
                <img src="https://img.icons8.com/?size=100&id=37795&format=png&color=000000" alt="Remove">
            </button>
        `;
        siteList.appendChild(li);
    });
}

function filter_elements() {
    const searchInput = document.querySelector(".search").value.toLowerCase();
    const filteredSites = sites.filter(site => site.toLowerCase().includes(searchInput));
    render_sites(filteredSites);
}

async function remove_site(site) {
    try {
        await fetch("http://127.0.0.1:8080/remove_site", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ site })
        });
        sites = sites.filter(s => s !== site);
        render_sites(sites);
    } catch (error) {
        console.error("Error removing site:", error);
    }
}



function add() {
    document.querySelector(".window_on_add").style.display = "block";
}

function close_add() {
    document.querySelector(".window_on_add").style.display = "none";
}

document.addEventListener("DOMContentLoaded", load_sites);
