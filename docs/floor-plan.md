# Floor plans

The Floor Plans page shows where devices are in a building. You create a
site, add floors to it, upload an image of each floor, and drag inventory
hosts onto the image. Each pin takes the color of the host's reachability, so
you can see which closet or room has a problem.

A site here is the same record as the **Site** on a host. See
[Device model](device-model.md) for how a host's site is set and used.

## Where it is and what you need

- Open **Observe > Floor Plans** in the sidebar. The page title is
  **Floor Plan Mapping**.
- You need the `floor-plan` feature. Every action on this page, including
  creating sites and moving pins, needs only that feature.
- To place hosts you also need the `inventory` feature. The list of hosts
  you can drag comes from the inventory.
- Have an image of each floor ready: JPEG, PNG, GIF, WebP or SVG, 20 MB at
  most.

The page has two panels. The left panel lists sites, and under the selected
site, its floors. The right panel shows the selected floor and its toolbar.

## Create a site

1. Select **+ Add Site** at the top of the page.
2. Fill in the **Add Site** dialog:

   | Field | Meaning |
   |---|---|
   | **Name \*** | Required. 200 characters at most. Must be unique. |
   | **Address** | Optional. A street address or a description. |
   | **Latitude** | Optional. -90 to 90. |
   | **Longitude** | Optional. -180 to 180. |

3. Select **Create Site**.

A name that already exists is refused with "Site name '...' already exists."

## Add a floor

1. Select the site in the left panel.
2. Select **+ Add Floor** in the toolbar.
3. Enter a **Floor Name \*** (required, 200 characters at most) and a
   **Floor Number** (a whole number, default `0`).
4. Select **Add Floor**.

Floors are listed by floor number, then by name. A floor name must be unique
within its site.

To change a floor, select it and choose **Edit Floor**. You can change the
name and the floor number, then select **Save**.

## Upload the floor image

1. Select the floor in the left panel.
2. Select **Upload Floor Plan**.
3. Choose the image file and select **Upload**.

Uploading again replaces the image. The old file is deleted. Pin positions
are kept, because they are stored relative to the image size (see below).

Until a floor has an image, the canvas shows "No floor plan image. Use
"Upload Floor Plan" to add one."

## Place hosts on a floor

1. Select the floor.
2. Tick **Edit pins** in the toolbar. A list named **UNPLACED DEVICES**
   opens below the image. It shows every inventory host that is not yet on
   this floor, with a dot in its status color.
3. Drag a host from the list and drop it on the image. The pin is saved
   where you drop it.
4. To move a pin, drag it to a new place while **Edit pins** is ticked. The
   new position is saved when you release the mouse.
5. Untick **Edit pins** when you are done. Pins cannot be moved while it is
   off.

When you place a host that has no site, the host takes the site of this
floor. A host that already has a site keeps it.

## Read the map

Each pin shows the first three letters of the host name. Hover over a pin to
see the full host name and IP address.

| Pin color | Host status | Meaning |
|---|---|---|
| Green | `up` | Polling reaches the device. |
| Red | `down` | Polling does not reach the device. |
| Gray | Anything else | No status yet, or an unknown status. |

Under each site name, the left panel shows:

| Item | Meaning |
|---|---|
| `N floors` | Floors in the site. |
| `N pinned` | Pins on all floors of the site. |
| `N hosts` | Inventory hosts whose **Site** is this site, placed or not. |
| Green dot and number | Pins whose host is `up`. |
| Red dot and number | Pins whose host is `down`. |
| Gray dot and number | Pins whose host has another status or none. |

A number in brackets after a floor name is the number of pins on that floor.
Select **Refresh** to reload the site list.

## Rules worth knowing

- **Pin positions are relative.** A pin is stored as two numbers from 0 to
  1: its distance across and down the image. Pins stay in the same place on
  the drawing when the browser scales the image, and after you upload a new
  image of the same layout.
- **One pin per host per floor.** Placing a host again on the same floor
  moves its pin. The same host can be placed on several floors; the
  **UNPLACED DEVICES** list only checks the floor you have open.
- **Status comes from monitoring.** Pin colors use the host status that
  polling sets. The floor plan does not poll devices itself.
- **Deleting a floor** asks first ("Delete floor "..." and all its device
  pins?"). It deletes the floor, its pins and its image file. Hosts are not
  changed.
- **Deleting a site** deletes its floors, their pins and their images. Hosts
  that had this site lose it (their **Site** becomes empty). VLANs that
  belong to the site are deleted too; see [VRFs and VLANs](vrfs-and-vlans.md).
  The page has no button for this; use the API.
- **Not on the page today:** editing a site, deleting a site and removing a
  single pin. The API supports all three (see below).
- **Deleting a host** removes its pins on every floor.
- **SVG images** are served with a strict content security policy, so a
  script inside an uploaded SVG does not run.
- **Image storage.** Images are stored on the server in the `floor_plans`
  folder of the installation, or in the folder named by the
  `GEO_FLOOR_PLAN_DIR` environment variable.

## Who can do what

| Action | Needs |
|---|---|
| See sites, floors, images and pins | The `floor-plan` feature |
| Create or change sites and floors, upload images | The `floor-plan` feature |
| Place, move or remove pins | The `floor-plan` feature |
| See the list of hosts to place | The `inventory` feature as well |

Admins pass every feature check. Every change is written to the audit log
under the `geolocation` category.

## API

All routes are under the same session and CSRF rules as the rest of the
Plexus API. Examples use invented data. See
[API reference](api-reference.md) for the full list.

```
GET    /api/geo/overview
GET    /api/geo/sites
POST   /api/geo/sites
GET    /api/geo/sites/{site_id}
PUT    /api/geo/sites/{site_id}
DELETE /api/geo/sites/{site_id}
POST   /api/geo/sites/{site_id}/floors
GET    /api/geo/floors/{floor_id}
PUT    /api/geo/floors/{floor_id}
DELETE /api/geo/floors/{floor_id}
POST   /api/geo/floors/{floor_id}/image
GET    /api/geo/floors/{floor_id}/image
GET    /api/geo/floors/{floor_id}/placements
PUT    /api/geo/floors/{floor_id}/placements/{host_id}
DELETE /api/geo/floors/{floor_id}/placements/{host_id}
```

Create a site:

```json
POST /api/geo/sites
{ "name": "HQ", "address": "1 Example Street", "lat": 51.5, "lng": -0.12 }
```

The answer is `201` with the new site. A duplicate name gives `409`.
`GET /api/geo/sites/{site_id}` returns the site with a `floors` list.

Upload an image as `multipart/form-data` with the file in the `file` field.
Another file type gives `400`; a file over 20 MB gives `413`.

Place or move a host:

```json
PUT /api/geo/floors/4/placements/42
{ "x_pct": 0.25, "y_pct": 0.6 }
```

```json
{
  "id": 9,
  "floor_id": 4,
  "host_id": 42,
  "x_pct": 0.25,
  "y_pct": 0.6,
  "created_at": "2026-11-14 09:30:00",
  "updated_at": "2026-11-14 09:30:00"
}
```

`x_pct` and `y_pct` must be between 0 and 1. An unknown floor or host gives
`404`. `GET /api/geo/floors/{floor_id}/placements` returns each pin with the
host's `hostname`, `ip_address` and `status`.
