/**
 * Virtual List — Renders only visible rows for large data sets.
 *
 * Usage:
 *   const vl = createVirtualList(scrollContainer, {
 *       items: myArray,
 *       rowHeight: 48,
 *       renderRow: (item, index) => `<div class="row">...</div>`,
 *       overscan: 5,
 *   });
 *   // When data changes:
 *   vl.update(newArray);
 *   // When done:
 *   vl.destroy();
 */

export function createVirtualList(container, options) {
    const {
        items: initialItems = [],
        rowHeight = 48,
        renderRow,
        overscan = 5,
    } = options;

    let items = initialItems;
    let scrollTop = 0;
    let rafId = null;

    // Sentinel element to maintain scroll height
    const spacer = document.createElement('div');
    spacer.style.cssText = 'width:100%;pointer-events:none;';

    // Viewport for rendered rows (absolutely positioned children)
    const viewport = document.createElement('div');
    viewport.style.cssText = 'position:relative;width:100%;';

    container.style.overflowY = 'auto';
    container.innerHTML = '';
    container.appendChild(spacer);
    container.appendChild(viewport);

    function render() {
        const totalHeight = items.length * rowHeight;
        spacer.style.height = `${totalHeight}px`;

        const viewportHeight = container.clientHeight || 400;
        const startIdx = Math.max(0, Math.floor(scrollTop / rowHeight) - overscan);
        const endIdx = Math.min(items.length, Math.ceil((scrollTop + viewportHeight) / rowHeight) + overscan);

        let html = '';
        for (let i = startIdx; i < endIdx; i++) {
            const rowHtml = renderRow(items[i], i);
            html += `<div style="position:absolute;top:${i * rowHeight}px;left:0;right:0;height:${rowHeight}px;overflow:hidden;">${rowHtml}</div>`;
        }
        viewport.innerHTML = html;
        viewport.style.height = `${totalHeight}px`;

        rafId = null;
    }

    function onScroll() {
        scrollTop = container.scrollTop;
        if (!rafId) rafId = requestAnimationFrame(render);
    }

    container.addEventListener('scroll', onScroll, { passive: true });

    // Initial render
    render();

    return {
        /** Replace items and re-render */
        update(newItems) {
            items = newItems;
            scrollTop = container.scrollTop;
            render();
        },
        /** Get current items */
        getItems() {
            return items;
        },
        /** Clean up */
        destroy() {
            container.removeEventListener('scroll', onScroll);
            if (rafId) cancelAnimationFrame(rafId);
            viewport.innerHTML = '';
            spacer.style.height = '0';
        },
    };
}
