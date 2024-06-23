function toggleNav() {
    var sidebar = document.getElementById("mySidebar");
    var sidebarWidth = sidebar.style.width;
    if (sidebarWidth === "250px") {
        sidebar.style.width = "0";
        document.getElementById("main").style.marginLeft = "0";
        sessionStorage.setItem('sidebarOpen', 'false');
    } else {
        sidebar.style.width = "250px";
        document.getElementById("main").style.marginLeft = "250px";
        sessionStorage.setItem('sidebarOpen', 'true');
    }
}

window.addEventListener('load', function () {
    var sidebarOpen = sessionStorage.getItem('sidebarOpen');
    if (sidebarOpen === 'true') {
        var sidebar = document.getElementById("mySidebar");
        sidebar.style.width = "250px";
        document.getElementById("main").style.marginLeft = "250px";
    }
});