function disabler(id, enabled)
{
    var elem = document.getElementById(id);
    if (enabled)
    {
        elem.removeAttribute("disabled")
    }
    else
    {
        elem.setAttribute("disabled", true)
    }
}