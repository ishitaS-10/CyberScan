async function startScan() {
    const target = document.getElementById("target").value;
    const loader = document.getElementById("loader");
    const resultsDiv = document.getElementById("results");

    loader.classList.remove("hidden");
    resultsDiv.innerHTML = "";

    try {
        const res = await fetch("/scan", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({target})
        });

        const data = await res.json();
        loader.classList.add("hidden");

        resultsDiv.innerHTML = `
            <div class="card">
                <h3>🔓 Open Ports</h3>
                <p>${Array.isArray(data.ports) ? data.ports.join(", ") : data.ports}</p>
            </div>

            <div class="card">
                <h3>🌐 Web Security</h3>
                <pre>${JSON.stringify(data.web, null, 2)}</pre>
            </div>
        `;
    } catch (err) {
        loader.classList.add("hidden");
        resultsDiv.innerHTML = `<p>Error scanning target</p>`;
    }
}