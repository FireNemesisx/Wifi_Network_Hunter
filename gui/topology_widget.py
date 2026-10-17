"""
İnteraktif Ağ Topolojisi Grafiği Bileşeni (PyQt6 QGraphicsView & QGraphicsScene).
Ağ geçidini (Router) merkezde konumlandırır, keşfedilen cihazları işletim sistemi renk
kodlu düğümlerle radyal radar halkaları üzerinde 60 FPS hızında akıcı olarak görüntüler.
"""

import math
from typing import Dict, Optional, List

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGraphicsView, QGraphicsScene,
    QGraphicsItem, QGraphicsEllipseItem, QGraphicsLineItem, QGraphicsTextItem,
    QPushButton, QLabel
)
from PyQt6.QtCore import Qt, QRectF, QPointF, pyqtSignal
from PyQt6.QtGui import (
    QPen, QBrush, QColor, QFont, QPainter, QRadialGradient
)

from core.models import DeviceAsset
from gui.styles import OS_COLORS


class TopologyNode(QGraphicsEllipseItem):
    """
    Topoloji grafiğindeki bir ağı veya cihazı temsil eden interaktif QGraphicsItem.
    """
    def __init__(self, asset: Optional[DeviceAsset] = None, is_gateway: bool = False, parent=None):
        super().__init__(parent)
        self.asset = asset
        self.is_gateway = is_gateway
        self.radius = 24 if is_gateway else 16
        self.setRect(-self.radius, -self.radius, self.radius * 2, self.radius * 2)

        self.setAcceptHoverEvents(True)
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsSelectable, True)
        self.setCursor(Qt.CursorShape.PointingHandCursor)

        self.label_item = QGraphicsTextItem(self)
        self.label_item.setDefaultTextColor(QColor("#f1f5f9"))
        font = QFont("Segoe UI", 8, QFont.Weight.Bold if is_gateway else QFont.Weight.Normal)
        self.label_item.setFont(font)
        self._update_text()

    def _update_text(self):
        if self.is_gateway:
            text = f"AĞ GEÇİDİ\n{self.asset.ip_address if self.asset else 'Router'}"
        else:
            name = self.asset.hostname or self.asset.ip_address if self.asset else "Cihaz"
            text = f"{name}\n{self.asset.ip_address if self.asset else ''}"
        
        self.label_item.setPlainText(text)
        bounds = self.label_item.boundingRect()
        self.label_item.setPos(-bounds.width() / 2, self.radius + 3)

    def paint(self, painter: QPainter, option, widget=None):
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        if self.is_gateway:
            base_color = QColor("#f59e0b")  # Altın sarısı
            glow_color = QColor(245, 158, 11, 40)
        elif self.asset and self.asset.is_rogue:
            base_color = QColor("#ef4444")  # Kırmızı (Yabancı/Rogue)
            glow_color = QColor(239, 68, 68, 80)
        else:
            os_name = self.asset.os_family if self.asset else "Bilinmiyor"
            hex_color = OS_COLORS.get(os_name, "#64748b")
            base_color = QColor(hex_color)
            glow_color = QColor(base_color.red(), base_color.green(), base_color.blue(), 40)

        # Dış Halka / Parlama (Glow)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QBrush(glow_color))
        painter.drawEllipse(QPointF(0, 0), self.radius + 6, self.radius + 6)

        # Radyal Gradyan
        gradient = QRadialGradient(QPointF(0, 0), self.radius)
        gradient.setColorAt(0.0, base_color.lighter(130))
        gradient.setColorAt(0.7, base_color)
        gradient.setColorAt(1.0, base_color.darker(140))

        # Kenarlık
        pen_color = QColor("#ffffff") if self.isSelected() else base_color.lighter(140)
        pen_width = 2.5 if self.isSelected() or (self.asset and self.asset.is_rogue) else 1.5
        painter.setPen(QPen(pen_color, pen_width))
        painter.setBrush(QBrush(gradient))
        painter.drawEllipse(QPointF(0, 0), self.radius, self.radius)

        # Merkez Noktası
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QBrush(QColor("#ffffff")))
        painter.drawEllipse(QPointF(0, 0), 2.5, 2.5)


class TopologyWidget(QWidget):
    """
    Ağ topolojisini radar benzeri bir QGraphicsScene üzerinde sunan arayüz bileşeni.
    """
    node_clicked = pyqtSignal(object)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.scene = QGraphicsScene(self)
        self.scene.setBackgroundBrush(QBrush(QColor("#080c14")))
        
        # Sabit radar koordinat alanı
        self.scene.setSceneRect(-360, -240, 720, 480)

        self.view = QGraphicsView(self.scene)
        self.view.setRenderHints(
            QPainter.RenderHint.Antialiasing |
            QPainter.RenderHint.SmoothPixmapTransform |
            QPainter.RenderHint.TextAntialiasing
        )
        self.view.setDragMode(QGraphicsView.DragMode.ScrollHandDrag)
        self.view.setStyleSheet("border: none; background: #080c14;")

        self._nodes: Dict[str, TopologyNode] = {}
        self._links: List[QGraphicsLineItem] = []
        self._radar_rings: List[QGraphicsItem] = []
        self.gateway_ip: Optional[str] = None
        self.gateway_node: Optional[TopologyNode] = None

        self._setup_ui()
        self._draw_radar_background()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)

        toolbar = QHBoxLayout()
        toolbar.setContentsMargins(8, 6, 8, 2)
        
        info_label = QLabel("Radyal Ağ Topolojisi Haritası (Tekerlek ile Yakınlaştır / Sürükle)")
        info_label.setStyleSheet("color: #64748b; font-size: 11px;")
        toolbar.addWidget(info_label)

        toolbar.addStretch()

        reset_btn = QPushButton("Görünümü Sıfırla")
        reset_btn.setFixedHeight(24)
        reset_btn.setStyleSheet("font-size: 11px; padding: 2px 8px;")
        reset_btn.clicked.connect(self.reset_view)
        toolbar.addWidget(reset_btn)

        layout.addLayout(toolbar)
        layout.addWidget(self.view)

    def _draw_radar_background(self):
        """Arka plana radar kılavuz halkaları ve eksen çizgileri çizer."""
        pen_ring = QPen(QColor(30, 41, 59, 80), 1, Qt.PenStyle.DashLine)
        for r in (90, 170, 250):
            item = self.scene.addEllipse(-r, -r, r * 2, r * 2, pen_ring)
            item.setZValue(-10)
            self._radar_rings.append(item)

        pen_cross = QPen(QColor(30, 41, 59, 50), 1, Qt.PenStyle.DotLine)
        h_line = self.scene.addLine(-320, 0, 320, 0, pen_cross)
        v_line = self.scene.addLine(0, -220, 0, 220, pen_cross)
        h_line.setZValue(-10)
        v_line.setZValue(-10)

    def set_gateway(self, ip: Optional[str], mac: Optional[str] = None):
        """Ağ Geçidi merkez düğümünü ayarlar."""
        self.gateway_ip = ip
        if not self.gateway_node:
            gw_asset = DeviceAsset(
                ip_address=ip or "192.168.1.1",
                mac_address=mac or "Gateway",
                hostname="Varsayılan Ağ Geçidi",
                os_family="Ağ Altyapısı (Cisco/BSD)"
            )
            self.gateway_node = TopologyNode(gw_asset, is_gateway=True)
            self.gateway_node.setPos(0, 0)
            self.gateway_node.setZValue(5)
            self.scene.addItem(self.gateway_node)
            self._nodes["GATEWAY"] = self.gateway_node
        else:
            if self.gateway_node.asset:
                if ip:
                    self.gateway_node.asset.ip_address = ip
                if mac:
                    self.gateway_node.asset.mac_address = mac
                self.gateway_node._update_text()

    def update_asset(self, asset: DeviceAsset):
        """Topoloji haritasına yeni cihaz ekler veya mevcut cihazı günceller."""
        key = asset.mac_address if asset.mac_address else asset.ip_address
        is_gw = (self.gateway_ip and asset.ip_address == self.gateway_ip)

        if is_gw:
            self.set_gateway(asset.ip_address, asset.mac_address)
            return

        if key in self._nodes:
            node = self._nodes[key]
            node.asset = asset
            node._update_text()
            node.update()
        else:
            node = TopologyNode(asset, is_gateway=False)
            node.setZValue(2)
            self.scene.addItem(node)
            self._nodes[key] = node

            self._recalculate_radial_layout()

    def _recalculate_radial_layout(self):
        """Keşfedilen cihazları ağ geçidi etrafında dairesel yörüngede dizer."""
        for link in self._links:
            self.scene.removeItem(link)
        self._links.clear()

        devices = [n for k, n in self._nodes.items() if not n.is_gateway]
        count = len(devices)
        if count == 0:
            return

        if not self.gateway_node:
            self.set_gateway(self.gateway_ip or "192.168.1.1")

        center_pos = QPointF(0, 0)
        orbit_radius = min(220, max(130, count * 18))

        angle_step = (2 * math.pi) / count
        for i, node in enumerate(devices):
            angle = i * angle_step
            x = center_pos.x() + orbit_radius * math.cos(angle)
            y = center_pos.y() + orbit_radius * math.sin(angle)
            node.setPos(x, y)

            # Ağ geçidine bağlantı çizgisi
            line = QGraphicsLineItem(center_pos.x(), center_pos.y(), x, y)
            pen = QPen(QColor(56, 189, 248, 50), 1.2, Qt.PenStyle.SolidLine)
            line.setPen(pen)
            line.setZValue(-2)
            self.scene.addItem(line)
            self._links.append(line)

        # Sahneyi uygun sınırlarda tut
        margin = orbit_radius + 90
        self.scene.setSceneRect(-margin, -margin * 0.75, margin * 2, margin * 1.5)

    def reset_view(self):
        """Tüm topolojiyi pencereye sığdıracak şekilde sıfırlar."""
        self.view.fitInView(self.scene.sceneRect(), Qt.AspectRatioMode.KeepAspectRatio)

    def wheelEvent(self, event):
        """Fare tekerleğiyle yumuşak yakınlaştırma."""
        zoom_factor = 1.15 if event.angleDelta().y() > 0 else 1 / 1.15
        self.view.scale(zoom_factor, zoom_factor)
